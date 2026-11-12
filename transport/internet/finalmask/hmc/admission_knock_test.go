package hmc

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestAdmissionKnockTokenConcurrentSlotsReleaseOnce(t *testing.T) {
	token := make([]byte, 18)
	copy(token, t.Name())
	var wg sync.WaitGroup
	var mu sync.Mutex
	var slots []*knockSlot
	for range 64 {
		wg.Go(func() {
			slot := acquireKnockSlot(token)
			if slot != nil {
				mu.Lock()
				slots = append(slots, slot)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if len(slots) != 2 {
		t.Fatalf("token admitted %d concurrent slots, want 2", len(slots))
	}
	for range 64 {
		wg.Go(func() { slots[0].release() })
	}
	wg.Wait()
	replacement := acquireKnockSlot(token)
	if replacement == nil || acquireKnockSlot(token) != nil {
		t.Fatal("double release stole a live token slot")
	}
	slots[1].release()
	replacement.release()
	activeKnocks.Lock()
	_, exists := activeKnocks.tokens[[18]byte(token)]
	activeKnocks.Unlock()
	if exists {
		t.Fatal("released token retained")
	}
}

func TestAdmissionCapturedKnockSlotsRelayExactly(t *testing.T) {
	a := testAdmission(t, 64, 16, 100, 100)
	cache := newReplayCache(16, time.Minute)
	source := netip.MustParseAddr("127.0.0.1")
	knock := loginKnock(testPassword, "localhost", "test_user", testLoginProfile("test_user").UUID, fallbackTime.Unix()/30)
	first := admissionAttempt(t, a, source, cache, fallbackTime, knock)
	second := admissionAttempt(t, a, source, cache, fallbackTime, knock)
	wire := loginStartWire(t, knock, 2, testLoginProfile("test_user").UUID)
	reply := []byte("exact vanilla response")
	fake := newFakeDest(t, func(conn net.Conn, r io.Reader) {
		want := rewriteHandshake(wire, conn.LocalAddr().String())
		got := make([]byte, len(want))
		if _, err := io.ReadFull(r, got); err != nil || !bytes.Equal(got, want) || bytes.Contains(got, []byte(knock)) {
			t.Error("over-cap knock relay changed recorded bytes", err)
			return
		}
		_ = writeFull(conn, reply)
	})
	raw, peer := tcpPair(t)
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(time.Second))
	server, err := wrapConnServer(peer, nil, testPassword, testPublicKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.limiter, server.knocks, server.now, server.dest = a, cache, func() time.Time { return fallbackTime }, fake.address()
	done := make(chan error, 1)
	go func() { done <- server.handshake() }()
	if err := writeFull(raw, wire); err != nil {
		t.Fatal(err)
	}
	if err := raw.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(raw)
	if err != nil || !bytes.Equal(got, reply) {
		t.Fatalf("third knock relay reply: %q %v", got, err)
	}
	if err := <-done; err == nil {
		t.Fatal("third concurrent knock accepted")
	}
	snapshots := fake.snapshots()
	if len(snapshots) != 1 || !bytes.Equal(snapshots[0], rewriteHandshake(wire, fake.address())) {
		t.Fatal("valid but over-cap knock not relayed exactly once")
	}
	first.raw.Close()
	if err := <-first.done; err == nil {
		t.Fatal("closed pending attempt succeeded")
	}
	replacement := admissionAttempt(t, a, source, cache, fallbackTime, knock)
	second.proof[len(second.proof)-1] ^= 1
	if err := writePacket(second.raw, 1, &second.secret, &second.proof); err != nil {
		t.Fatal(err)
	}
	if err := <-second.done; err == nil {
		t.Fatal("garbage proof accepted")
	}
	if !replacement.finish(t) {
		t.Fatal("released knock slot could not authenticate")
	}
	if a.pre != 0 {
		t.Fatal("knock slots leaked admission")
	}
	activeKnocks.Lock()
	_, exists := activeKnocks.tokens[[18]byte(knockToken(knock))]
	activeKnocks.Unlock()
	if exists {
		t.Fatal("completed handshake retained token counter")
	}
}
