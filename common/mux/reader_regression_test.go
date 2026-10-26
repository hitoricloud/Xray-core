package mux_test

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
)

func TestPacketReaderOwnsDestination(t *testing.T) {
	dest := net.UDPDestination(net.LocalHostIP, 1234)
	want := dest
	reader := mux.NewPacketReader(bytes.NewReader([]byte{0, 1, 'x'}), &dest)
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	dest.Port = 5678
	if mb[0].UDP == nil || *mb[0].UDP != want {
		t.Fatal("an earlier packet's destination changed with the next frame")
	}
}

func TestPacketReaderNilDestination(t *testing.T) {
	reader := mux.NewPacketReader(bytes.NewReader([]byte{0, 1, 'x'}), nil)
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	if mb[0].UDP != nil {
		t.Fatal("nil destination became a UDP destination")
	}
}
