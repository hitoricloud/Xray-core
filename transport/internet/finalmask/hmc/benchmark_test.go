package hmc

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func BenchmarkPacketDecode(b *testing.B) {
	payload := bytes.Repeat([]byte("a"), maxPacketData)
	channel := String(packetChannel)
	data := RestBytes(payload)
	frame, err := encodePacket(configurationServerboundCustomPayload, &channel, &data)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet, err := readPacket(bytes.NewReader(frame))
		if err != nil {
			b.Fatal(err)
		}
		if _, ok, err := parseCustomPayload(packet); err != nil || !ok {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyLoginResponseFailure(b *testing.B) {
	secret, proof := make([]byte, fieldLength), make([]byte, fieldLength)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := verifyLoginResponse(testPassword, []byte("public key"), []byte{1, 2, 3, 4}, secret, proof); err != errInvalidLogin {
			b.Fatal(err)
		}
	}
}

func BenchmarkCryptoWrite(b *testing.B) {
	writer, err := newCryptoWriter(io.Discard, streamKey{})
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, maxPacketData)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := writer.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamThroughput(b *testing.B) {
	profile, publicKey := testLoginProfile("bench_user"), testPublicKey(b)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		server, err := wrapConnServer(raw, []loginProfile{profile}, testPassword, publicKey)
		if err == nil {
			_, _ = io.Copy(io.Discard, server)
		}
		raw.Close()
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	client, err := newClientConn(raw, []loginProfile{profile}, testPassword, "localhost")
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()
	chunk := make([]byte, 1<<20)
	if _, err := client.Write(chunk[:1]); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(chunk)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
}
