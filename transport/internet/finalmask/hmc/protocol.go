// Minecraft protocol
package hmc

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

const (
	maxPacketDataLength = 32 * 1024
	maxPacketBodyLength = maxPacketDataLength + 5
)

type field interface {
	readFrom(r io.Reader) error
	writeTo(w io.Writer) error
}

type mcPacket struct {
	packetID int
	data     []byte
}

func readPacket(b io.Reader) (*mcPacket, error) {
	packet, _, err := readPacketWithLength(b)
	return packet, err
}

// Unauthenticated peers get a small frame limit so slow clients cannot make
// the server allocate large buffers before proving they know the password.
const preAuthPacketBodyLength = 1024

func readPacketWithLength(b io.Reader) (*mcPacket, int, error) {
	return readPacketWithLimit(b, maxPacketBodyLength)
}

func readPreAuthPacket(b io.Reader) (*mcPacket, error) {
	packet, _, err := readPacketWithLimit(b, preAuthPacketBodyLength)
	return packet, err
}

func readPacketWithLimit(b io.Reader, limit int) (*mcPacket, int, error) {
	return readPacketReusing(b, limit, nil)
}

// A non-nil scratch is reused for the frame: the returned packet data is only
// valid until the next read that uses the same scratch.
func readPacketReusing(b io.Reader, limit int, scratch *[]byte) (*mcPacket, int, error) {
	packet := new(mcPacket)
	wireLength, err := readPacketInto(b, limit, scratch, packet)
	if err != nil {
		return nil, 0, err
	}
	return packet, wireLength, nil
}

// readPacketInto fills out in place, so a hot loop can reuse one mcPacket.
func readPacketInto(b io.Reader, limit int, scratch *[]byte, out *mcPacket) (int, error) {
	packetData, wireLength, err := readFrame(b, limit, scratch)
	if err != nil {
		return 0, err
	}
	return wireLength, decodePacketBodyInto(packetData, out)
}

func decodePacketBody(packetData []byte) (*mcPacket, error) {
	packet := new(mcPacket)
	if err := decodePacketBodyInto(packetData, packet); err != nil {
		return nil, err
	}
	return packet, nil
}

func decodePacketBodyInto(packetData []byte, out *mcPacket) error {
	if len(packetData) < 1 || len(packetData) > maxPacketBodyLength {
		return fmt.Errorf("read packet: bad length: %d", len(packetData))
	}

	packetID, idLength, err := parseVarint(packetData)
	if err != nil {
		return fmt.Errorf("read packet ID: %w", err)
	}

	dataLength := len(packetData) - idLength
	if dataLength > maxPacketDataLength {
		return fmt.Errorf("read packet: bad length: %d", dataLength)
	}

	out.packetID = int(packetID)
	out.data = packetData[len(packetData)-dataLength:]
	return nil
}

func readFrame(r io.Reader, maxLength int, scratch *[]byte) ([]byte, int, error) {
	frameLength, prefixLength, err := readVarintWithLength(r)
	if err != nil {
		if errors.Is(err, io.EOF) {
			if prefixLength == 0 {
				return nil, 0, io.EOF
			}
			err = io.ErrUnexpectedEOF
		}
		return nil, 0, fmt.Errorf("read packet length: %w", err)
	}
	if frameLength < 1 || int(frameLength) > maxLength {
		return nil, 0, fmt.Errorf("read packet: bad length: %d", frameLength)
	}

	var frame []byte
	if scratch != nil {
		if cap(*scratch) < int(frameLength) {
			*scratch = make([]byte, int(frameLength))
		}
		frame = (*scratch)[:int(frameLength)]
	} else {
		frame = make([]byte, int(frameLength))
	}
	if _, err := io.ReadFull(r, frame); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, 0, fmt.Errorf("read packet data: %w", err)
	}
	return frame, prefixLength + len(frame), nil
}

func (p *mcPacket) readFields(fields ...field) error {
	r := bytes.NewReader(p.data)
	for _, field := range fields {
		err := field.readFrom(r)
		if err != nil {
			return fmt.Errorf("read packet field: %w", err)
		}
	}

	return nil
}

type Varint int32

const (
	SEGMENT_BITS = 0x7F
	CONTINUE_BIT = 0x80
)

func (v *Varint) readFrom(r io.Reader) error {
	value, _, err := readVarintWithLength(r)
	if err != nil {
		return err
	}
	*v = value
	return nil
}

// parseVarint decodes a canonical VarInt from the start of b without allocating;
// it accepts exactly what readVarintWithLength accepts.
func parseVarint(b []byte) (Varint, int, error) {
	var value int32
	for index := 0; index < 5; index++ {
		if index >= len(b) {
			return 0, 0, fmt.Errorf("read varint: %w", io.ErrUnexpectedEOF)
		}
		currentByte := b[index]
		if index == 4 && currentByte&0xf0 != 0 {
			return 0, 0, fmt.Errorf("read varint: too large")
		}
		value |= int32(currentByte&SEGMENT_BITS) << (7 * index)
		if currentByte&CONTINUE_BIT == 0 {
			parsed := Varint(value)
			if index+1 != varintSize(parsed) {
				return 0, 0, fmt.Errorf("read varint: non-canonical encoding")
			}
			return parsed, index + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("read varint: too large")
}

func readVarintWithLength(r io.Reader) (Varint, int, error) {
	var value int32
	for index := 0; index < 5; index++ {
		currentByte, err := readByte(r)
		if err != nil {
			return 0, index, fmt.Errorf("read varint: %w", err)
		}
		if index == 4 && currentByte&0xf0 != 0 {
			return 0, 0, fmt.Errorf("read varint: too large")
		}
		value |= int32(currentByte&SEGMENT_BITS) << (7 * index)

		if currentByte&CONTINUE_BIT == 0 {
			parsed := Varint(value)
			length := index + 1
			if length != varintSize(parsed) {
				return 0, 0, fmt.Errorf("read varint: non-canonical encoding")
			}
			return parsed, length, nil
		}
	}
	return 0, 0, fmt.Errorf("read varint: too large")
}

func (v *Varint) writeTo(w io.Writer) error {
	value := uint32(*v)

	for {
		currentByte := byte(value & SEGMENT_BITS)
		value >>= 7
		if value != 0 {
			currentByte |= CONTINUE_BIT
		}

		_, err := w.Write([]byte{currentByte})
		if err != nil {
			return fmt.Errorf("write varint: %w", err)
		}

		if value == 0 {
			break
		}
	}

	return nil
}

func appendVarint(dst []byte, value Varint) []byte {
	v := uint32(value)
	for v >= 0x80 {
		dst = append(dst, byte(v)|CONTINUE_BIT)
		v >>= 7
	}
	return append(dst, byte(v))
}

func varintSize(value Varint) int {
	uintValue := uint32(value)
	size := 0
	for range 5 {
		size++
		uintValue >>= 7
		if uintValue == 0 {
			break
		}
	}
	return size
}

type String string

func (v *String) readFrom(r io.Reader) error {
	var length Varint = 0

	err := length.readFrom(r)
	if err != nil {
		return fmt.Errorf("read string: %w", err)
	}

	if length < 0 || length > 4096 {
		return fmt.Errorf("read string: bad length: %d", length)
	}

	buf := make([]byte, length)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return fmt.Errorf("read string: %w", err)
	}

	*v = String(string(buf))

	return nil
}

func (v *String) writeTo(w io.Writer) error {
	strBytes := []byte(*v)
	length := Varint(len(strBytes))

	err := length.writeTo(w)
	if err != nil {
		return fmt.Errorf("write string: %w", err)
	}

	_, err = w.Write(strBytes)
	if err != nil {
		return fmt.Errorf("write string: %w", err)
	}

	return nil
}

type UnsignedShort uint16

func (v *UnsignedShort) readFrom(r io.Reader) error {
	var buf [2]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return fmt.Errorf("read unsigned short: %w", err)
	}

	*v = UnsignedShort(buf[0])<<8 | UnsignedShort(buf[1])

	return nil
}

func (v *UnsignedShort) writeTo(w io.Writer) error {
	buf := []byte{byte(*v >> 8), byte(*v & 0xFF)}
	_, err := w.Write(buf)
	if err != nil {
		return fmt.Errorf("write unsigned short: %w", err)
	}
	return nil
}

type Long int64

func (v *Long) readFrom(r io.Reader) error {
	var buf [8]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return fmt.Errorf("read long: %w", err)
	}

	*v = Long(buf[0])<<56 | Long(buf[1])<<48 | Long(buf[2])<<40 | Long(buf[3])<<32 |
		Long(buf[4])<<24 | Long(buf[5])<<16 | Long(buf[6])<<8 | Long(buf[7])

	return nil
}

func (v *Long) writeTo(w io.Writer) error {
	buf := []byte{
		byte(*v >> 56), byte((*v >> 48) & 0xFF), byte((*v >> 40) & 0xFF), byte((*v >> 32) & 0xFF),
		byte((*v >> 24) & 0xFF), byte((*v >> 16) & 0xFF), byte((*v >> 8) & 0xFF), byte(*v & 0xFF),
	}

	_, err := w.Write(buf)
	if err != nil {
		return fmt.Errorf("write long: %w", err)
	}

	return nil
}

type UUID [16]byte

func (v *UUID) readFrom(r io.Reader) error {
	_, err := io.ReadFull(r, v[:])
	if err != nil {
		return fmt.Errorf("read UUID: %w", err)
	}

	return nil
}

type Boolean bool

func (v *Boolean) readFrom(r io.Reader) error {
	b, err := readByte(r)
	if err != nil {
		return fmt.Errorf("read boolean: %w", err)
	}
	if b > 1 {
		return fmt.Errorf("read boolean: invalid value: %d", b)
	}
	*v = b == 1
	return nil
}

func (v *Boolean) writeTo(w io.Writer) error {
	value := byte(0)
	if *v {
		value = 1
	}
	if _, err := w.Write([]byte{value}); err != nil {
		return fmt.Errorf("write boolean: %w", err)
	}
	return nil
}

func (v *UUID) writeTo(w io.Writer) error {
	_, err := w.Write(v[:])
	if err != nil {
		return fmt.Errorf("write UUID: %w", err)
	}
	return nil
}

type Bytes []byte

func (v *Bytes) readFrom(r io.Reader) error {
	var length Varint
	err := length.readFrom(r)
	if err != nil {
		return fmt.Errorf("read bytes: %w", err)
	}

	if length < 0 || length > maxPacketDataLength {
		return fmt.Errorf("read bytes: invalid size: %d", length)
	}

	buf := make([]byte, length)

	_, err = io.ReadFull(r, buf)
	if err != nil {
		return fmt.Errorf("read bytes: %w", err)
	}

	*v = append([]byte(*v), buf...)

	return nil
}

type RestBytes []byte

func (v *RestBytes) readFrom(r io.Reader) error {
	buf, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read remaining bytes: %w", err)
	}
	*v = append((*v)[:0], buf...)
	return nil
}

func (v *RestBytes) writeTo(w io.Writer) error {
	if _, err := w.Write(*v); err != nil {
		return fmt.Errorf("write remaining bytes: %w", err)
	}
	return nil
}

func (v *Bytes) writeTo(w io.Writer) error {
	length := Varint(len(*v))
	err := length.writeTo(w)
	if err != nil {
		return fmt.Errorf("write bytes length: %w", err)
	}

	_, err = w.Write(*v)
	if err != nil {
		return fmt.Errorf("write bytes: %w", err)
	}

	return nil
}

func readByte(r io.Reader) (byte, error) {
	if br, ok := r.(io.ByteReader); ok {
		b, err := br.ReadByte()
		if err != nil {
			return 0, fmt.Errorf("read byte: %w", err)
		}
		return b, nil
	}
	var buf [1]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return 0, fmt.Errorf("read byte: %w", err)
	}

	return buf[0], nil
}

func writePacket(w io.Writer, packetID int, fields ...field) error {
	_, err := writePacketWithLength(w, packetID, fields...)
	return err
}

func writePacketWithLength(w io.Writer, packetID int, fields ...field) (int, error) {
	frame, err := encodePacket(packetID, fields...)
	if err != nil {
		return 0, err
	}
	if err = writeFull(w, frame); err != nil {
		return 0, fmt.Errorf("write packet data: %w", err)
	}
	return len(frame), nil
}

func encodePacket(packetID int, fields ...field) ([]byte, error) {
	var dataBuf bytes.Buffer

	for _, field := range fields {
		err := field.writeTo(&dataBuf)
		if err != nil {
			return nil, fmt.Errorf("write packet field: %w", err)
		}
	}
	if dataBuf.Len() > maxPacketDataLength {
		return nil, fmt.Errorf("write packet: bad length: %d", dataBuf.Len())
	}

	packetIDVarint := Varint(packetID)
	bodyLength := varintSize(packetIDVarint) + dataBuf.Len()
	if bodyLength > maxPacketBodyLength {
		return nil, fmt.Errorf("write packet: bad length: %d", bodyLength)
	}

	var frame bytes.Buffer
	frame.Grow(varintSize(Varint(bodyLength)) + bodyLength)
	frameLength := Varint(bodyLength)
	if err := frameLength.writeTo(&frame); err != nil {
		return nil, fmt.Errorf("write packet length: %w", err)
	}
	if err := packetIDVarint.writeTo(&frame); err != nil {
		return nil, fmt.Errorf("write packet ID: %w", err)
	}
	frame.Write(dataBuf.Bytes())
	return frame.Bytes(), nil
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func writeDisconnectPacket(w io.Writer, reason string) error {
	return writePacket(w, 0x00, new(String(reason)))
}
