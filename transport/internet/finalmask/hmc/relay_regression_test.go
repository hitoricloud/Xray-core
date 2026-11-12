package hmc

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestRelayIdlePreservesDestFinalMessage(t *testing.T) {
	if fallbackLimits.idle != 90*time.Second {
		t.Errorf("default idle = %v, want 90s", fallbackLimits.idle)
	}
	const silence = 210 * time.Millisecond
	msg := []byte("LOGIN-DISCONNECT slow_login")
	fake := newFakeDest(t, func(conn net.Conn, reader io.Reader) {
		if _, err := io.ReadFull(reader, make([]byte, 5)); err != nil {
			return
		}
		time.Sleep(silence)
		_ = writeFull(conn, msg)
	})
	garbage := []byte{0xff, 0xff, 0xff, 0xff, 0xff}
	direct, err := net.Dial("tcp", fake.address())
	if err != nil {
		t.Fatal(err)
	}
	_ = direct.SetDeadline(time.Now().Add(2 * time.Second))
	_ = writeFull(direct, garbage)
	want, err := io.ReadAll(direct)
	direct.Close()
	if err != nil || !bytes.Equal(want, msg) {
		t.Fatalf("direct=%q %v", want, err)
	}
	limits := fallbackLimits
	limits.idle, limits.total, limits.slots = fallbackLimits.idle/300, 2*time.Second, make(chan struct{}, 1)
	raw, _, done := fallbackPair(t, fake.address(), newReplayCache(16, time.Minute), &limits)
	_ = writeFull(raw, garbage)
	got, err := io.ReadAll(raw)
	<-done
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("relay lost final message: %q %v", got, err)
	}
}

func TestRelayIdleSharedAcrossDirections(t *testing.T) {
	limits := relayLimits{150 * time.Millisecond, 3 * time.Second, 1 << 20, 1 << 20, make(chan struct{}, 1)}
	msg := []byte("final")
	fake := newFakeDest(t, func(conn net.Conn, reader io.Reader) {
		if _, err := io.ReadFull(reader, make([]byte, 5)); err != nil {
			return
		}
		for range 6 {
			time.Sleep(40 * time.Millisecond)
			if writeFull(conn, []byte(".")) != nil {
				return
			}
		}
		_ = writeFull(conn, msg)
	})
	raw, _, done := fallbackPair(t, fake.address(), newReplayCache(16, time.Minute), &limits)
	_ = writeFull(raw, []byte{0xff, 0xff, 0xff, 0xff, 0xff})
	got, err := io.ReadAll(raw)
	<-done
	if err != nil || string(got) != "......final" {
		t.Fatalf("one-way activity cut off: %q %v", got, err)
	}
}

func TestRelayIdleUploadKeepsDownloadAlive(t *testing.T) {
	limits := relayLimits{150 * time.Millisecond, 3 * time.Second, 1 << 20, 1 << 20, make(chan struct{}, 1)}
	fake := newFakeDest(t, func(conn net.Conn, reader io.Reader) {
		if _, err := io.ReadFull(reader, make([]byte, 11)); err != nil {
			return
		}
		_ = writeFull(conn, []byte("final"))
	})
	raw, _, done := fallbackPair(t, fake.address(), newReplayCache(16, time.Minute), &limits)
	_ = writeFull(raw, []byte{0xff, 0xff, 0xff, 0xff, 0xff})
	for range 6 {
		time.Sleep(40 * time.Millisecond)
		if err := writeFull(raw, []byte(".")); err != nil {
			t.Fatal(err)
		}
	}
	got, err := io.ReadAll(raw)
	<-done
	if err != nil || string(got) != "final" {
		t.Fatalf("upload did not keep download alive: %q %v", got, err)
	}
}

func TestLegacyPingRelaysImmediately(t *testing.T) {
	received := make(chan time.Time, 1)
	fake := newFakeDest(t, func(conn net.Conn, reader io.Reader) {
		first := make([]byte, 1)
		if _, err := io.ReadFull(reader, first); err == nil && first[0] == 0xfe {
			received <- time.Now()
			_ = writeFull(conn, []byte{0xff, 0, 1, 0, 0x41})
		}
	})
	raw, server, done := fallbackPair(t, fake.address(), newReplayCache(16, time.Minute), nil)
	_ = server.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	start := time.Now()
	_ = writeFull(raw, []byte{0xfe, 0x01, 0xfa, 0, 0x0b})
	select {
	case at := <-received:
		if at.Sub(start) >= 50*time.Millisecond {
			t.Errorf("first byte delayed %v", at.Sub(start))
		}
	case <-time.After(50 * time.Millisecond):
		t.Error("dest did not see legacy ping within 50ms")
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(raw, reply); err != nil {
		t.Error(err)
	}
	raw.Close()
	<-done
}
