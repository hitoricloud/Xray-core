package hmc

import (
	"bytes"
	"testing"
)

func FuzzVerifyLoginResponse(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 128), make([]byte, 128))
	f.Fuzz(func(t *testing.T, secret, proof []byte) {
		_, _ = verifyLoginResponse(testPassword, []byte("public key"), []byte{1, 2, 3, 4}, secret, proof)
	})
}

func FuzzReadPacket(f *testing.F) {
	f.Add([]byte{1, 3})
	f.Add([]byte{0x81, 0, 3})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		packet, err := readPacket(bytes.NewReader(data))
		if err != nil {
			return
		}
		if len(packet.data) > maxPacketDataLength {
			t.Fatal("packet exceeded maximum")
		}
		_, _, _ = parseCustomPayload(packet)
	})
}
