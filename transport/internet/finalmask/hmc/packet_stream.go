package hmc

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	configurationClientboundCustomPayload = 0x01
	configurationServerboundCustomPayload = 0x02
	configurationKeepAlive                = 0x04

	packetChannel = "hmc:data"
	maxPacketData = 24 * 1024
)

// Variable so tests can shorten it.
var keepAlivePeriod = 15 * time.Second

// packetStream carries the raw proxy byte stream in Minecraft configuration
// custom payload packets. The configuration state provides bidirectional
// payload packets and keep-alives without requiring version-specific world data.
type packetStream struct {
	reader   io.Reader
	writer   io.Writer
	isClient bool

	readMu      sync.Mutex
	writeMu     sync.Mutex
	readErr     error
	writeErr    error
	pending     []byte
	frameBuf    []byte // read scratch, guarded by readMu
	packetBuf   mcPacket
	frameReader countingReader
	wireBuf     []byte // outbound frame, guarded by writeMu

	keepAliveID      atomic.Int64
	keepAliveReplies chan Long
	done             chan struct{}
	stopOnce         sync.Once
}

func newPacketStream(reader io.Reader, writer io.Writer, isClient bool) *packetStream {
	s := &packetStream{
		reader:   reader,
		writer:   writer,
		isClient: isClient,
		done:     make(chan struct{}),
	}
	if isClient {
		s.keepAliveReplies = make(chan Long, 1)
		go s.keepAliveReplyLoop()
	} else {
		go s.keepAliveLoop()
	}
	return s
}

// Replies are sent outside Read, which holds readMu: a write blocked by peer
// backpressure must not stop the reader that would relieve that pressure.
func (s *packetStream) keepAliveReplyLoop() {
	for {
		select {
		case id := <-s.keepAliveReplies:
			if s.writeKeepAlive(id) != nil {
				return
			}
		case <-s.done:
			return
		}
	}
}

func (s *packetStream) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.readErr != nil {
		return 0, s.readErr
	}
	transient := false
	defer func() {
		if err != nil && !transient {
			s.readErr = err
			s.Stop()
		}
	}()

	if len(s.pending) > 0 {
		n := copy(p, s.pending)
		s.pending = s.pending[n:]
		return n, nil
	}

	for {
		s.frameReader = countingReader{r: s.reader}
		frame := &s.frameReader
		packet := &s.packetBuf
		_, err := readPacketInto(frame, maxPacketBodyLength, &s.frameBuf, packet)
		if err != nil {
			err = streamError("read minecraft packet stream", err)
			// A timeout before any frame byte leaves the stream synchronized.
			var timeout net.Error
			transient = frame.n == 0 && errors.As(err, &timeout) && timeout.Timeout()
			return 0, err
		}

		if packet.packetID == s.remoteCustomPayloadID() {
			payload, ok, err := parseCustomPayload(packet)
			if err != nil {
				return 0, err
			}
			if !ok || len(payload) == 0 {
				continue
			}

			n := copy(p, payload)
			if n < len(payload) {
				// payload aliases frameBuf, which is not reused until pending drains (readMu held).
				s.pending = payload[n:]
			}
			return n, nil
		}

		if packet.packetID == configurationKeepAlive {
			var id Long
			if err := packet.readFields(&id); err != nil {
				return 0, fmt.Errorf("read minecraft keep-alive: %w", err)
			}
			if s.isClient {
				select {
				case s.keepAliveReplies <- id:
				default:
				}
			}
		}
	}
}

func (s *packetStream) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	defer func() {
		if err != nil {
			s.writeErr = err
			s.Stop()
		}
	}()

	written := 0
	for written < len(p) {
		end := written + maxPacketData
		if end > len(p) {
			end = len(p)
		}
		id := Varint(s.localCustomPayloadID())
		body := varintSize(id) + varintSize(Varint(len(packetChannel))) + len(packetChannel) + (end - written)
		frame := appendVarint(s.wireBuf[:0], Varint(body))
		frame = appendVarint(frame, id)
		frame = appendVarint(frame, Varint(len(packetChannel)))
		frame = append(frame, packetChannel...)
		frame = append(frame, p[written:end]...)
		s.wireBuf = frame
		if err := writeFull(s.writer, frame); err != nil {
			return written, streamError("write minecraft custom payload", err)
		}
		written = end
	}

	return written, nil
}

type countingReader struct {
	r   io.Reader
	n   int
	one [1]byte
}

func (c *countingReader) ReadByte() (byte, error) {
	if br, ok := c.r.(io.ByteReader); ok {
		b, err := br.ReadByte()
		if err == nil {
			c.n++
		}
		return b, err
	}
	n, err := io.ReadFull(c.r, c.one[:])
	c.n += n
	return c.one[0], err
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func (s *packetStream) Stop() {
	s.stopOnce.Do(func() { close(s.done) })
}

func (s *packetStream) localCustomPayloadID() int {
	if s.isClient {
		return configurationServerboundCustomPayload
	}
	return configurationClientboundCustomPayload
}

func (s *packetStream) remoteCustomPayloadID() int {
	if s.isClient {
		return configurationClientboundCustomPayload
	}
	return configurationServerboundCustomPayload
}

func parseCustomPayload(packet *mcPacket) ([]byte, bool, error) {
	// Fast path for the only channel HMC uses, without allocating a string.
	if n := len(packetChannel); len(packet.data) > n && int(packet.data[0]) == n && string(packet.data[1:1+n]) == packetChannel {
		return packet.data[1+n:], true, nil
	}
	r := bytes.NewReader(packet.data)
	var channel String
	if err := channel.readFrom(r); err != nil {
		return nil, false, fmt.Errorf("read minecraft custom payload channel: %w", err)
	}
	if string(channel) != packetChannel {
		return nil, false, nil
	}
	return packet.data[len(packet.data)-r.Len():], true, nil
}

func (s *packetStream) writeKeepAlive(id Long) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeErr != nil {
		return s.writeErr
	}
	if err := writePacket(s.writer, configurationKeepAlive, &id); err != nil {
		s.writeErr = streamError("write minecraft keep-alive", err)
		s.Stop()
		return s.writeErr
	}
	return nil
}

// Preserve the net.Conn timeout contract without making a partially consumed
// frame retryable. Other failures retain their contextual error wrapping.
func streamError(operation string, err error) error {
	if err == io.EOF {
		return io.EOF
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		return networkError
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func (s *packetStream) keepAliveLoop() {
	ticker := time.NewTicker(keepAlivePeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			id := Long(s.keepAliveID.Add(1))
			if err := s.writeKeepAlive(id); err != nil {
				return
			}
		case <-s.done:
			return
		}
	}
}
