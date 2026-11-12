package xudp

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// Record the existing XUDP limit separately from transport smoke tests: an
// oversized datagram is dropped here even without TLS or a FinalMask.
func TestPacketWriterPayloadLimit(t *testing.T) {
	for _, size := range []int{1472, buf.Size - 666, buf.Size - 665, buf.Size} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			var output buf.MultiBufferContainer
			defer func() { buf.ReleaseMulti(output.MultiBuffer) }()
			writer := NewPacketWriter(&output, net.UDPDestination(net.LocalHostIP, 1234), [8]byte{})
			payload := bytes.Repeat([]byte{0x42}, size)
			packet := buf.New()
			if _, err := packet.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
				t.Fatal(err)
			}
			if size > buf.Size-666 {
				if len(output.MultiBuffer) != 0 {
					t.Fatal("oversized datagram was not dropped")
				}
			} else if len(output.MultiBuffer) != 1 || !bytes.HasSuffix(output.MultiBuffer[0].Bytes(), payload) {
				t.Fatal("in-range datagram was lost or corrupted")
			}
		})
	}
}

func TestXudpReadWrite(t *testing.T) {
	addr, _ := net.ParseDestination("tcp:127.0.0.1:1345")
	mb := make(buf.MultiBuffer, 0, 16)
	m := buf.MultiBufferContainer{
		MultiBuffer: mb,
	}
	var arr [8]byte
	writer := NewPacketWriter(&m, addr, arr)

	source := make(buf.MultiBuffer, 0, 16)
	b := buf.New()
	b.WriteByte('a')
	b.UDP = &addr
	source = append(source, b)
	writer.WriteMultiBuffer(source)

	reader := NewPacketReader(&m)
	dest, err := reader.ReadMultiBuffer()
	common.Must(err)
	if dest[0].Byte(0) != 'a' {
		t.Error("failed to parse xudp buffer")
	}
	if dest[0].UDP.Port != 1345 {
		t.Error("failed to parse xudp buffer")
	}
}
