package hmc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func probeReply(conn net.Conn, reader io.Reader, key []byte, id String) {
	if _, err := readPacket(reader); err != nil {
		return
	}
	if _, err := readPacket(reader); err != nil {
		return
	}
	public, token := Bytes(key), Bytes{1, 2, 3, 4}
	_ = writePacket(conn, 1, &id, &public, &token)
}

func installDestEntry(dest string, version uint32, entry *destEntry) {
	destKeys.Store(destKey(dest, version), entry)
}

func forceDestRefresh(t *testing.T, dest string, version uint32, entry *destEntry) {
	t.Helper()
	entry.mu.Lock()
	entry.next = time.Time{}
	entry.mu.Unlock()
	PrepareDest(dest, version)
	waitDest(t, dest, version)
}

func TestDestProbeTwoSamplesOneSecondApart(t *testing.T) {
	key := testPublicKey(t)
	samples := make(chan time.Time, 2)
	fake := newFakeDest(t, func(conn net.Conn, reader io.Reader) {
		samples <- time.Now()
		probeReply(conn, reader, key, "0")
	})
	PrepareDest(fake.address(), 0)
	waitDest(t, fake.address())
	first, second := <-samples, <-samples
	if elapsed := second.Sub(first); elapsed < 900*time.Millisecond {
		t.Fatalf("samples only %v apart", elapsed)
	}
}

func TestDestStaticIDAndKeyStayStatic(t *testing.T) {
	key := testPublicKey(t)
	fake := newFakeDest(t, func(conn net.Conn, reader io.Reader) { probeReply(conn, reader, key, "0") })
	entry := newDestEntry()
	entry.sampleDelay = 5 * time.Millisecond
	installDestEntry(fake.address(), 0, entry)
	PrepareDest(fake.address(), 0)
	waitDest(t, fake.address())
	for range 100 {
		got, id := cachedDest(fake.address(), 0)
		if !bytes.Equal(got, key) || id != "0" {
			t.Fatalf("static dest changed: id=%q key=%x", id, got)
		}
	}
	forceDestRefresh(t, fake.address(), 0, entry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if len(entry.keys) != 1 || entry.randomID {
		t.Fatal("static samples not deduplicated")
	}
}

func TestDestRotatingIDsAndEightKeyPool(t *testing.T) {
	keys := make([][]byte, 10)
	for i := range keys {
		private, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		keys[i], err = x509.MarshalPKIXPublicKey(&private.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	var counter atomic.Int32
	fake := newFakeDest(t, func(conn net.Conn, reader io.Reader) {
		i := int(counter.Add(1)-1) % len(keys)
		probeReply(conn, reader, keys[i], String(fmt.Sprintf("%x", i+1)))
	})
	entry := newDestEntry()
	entry.sampleDelay = 5 * time.Millisecond
	installDestEntry(fake.address(), 0, entry)
	for range 5 {
		forceDestRefresh(t, fake.address(), 0, entry)
	}
	entry.mu.Lock()
	if len(entry.keys) != 8 || !entry.randomID {
		t.Errorf("pool=%d random=%v", len(entry.keys), entry.randomID)
	}
	for i, key := range entry.keys {
		if !bytes.Equal(key, keys[i+2]) {
			t.Error("oldest key not dropped")
		}
	}
	entry.mu.Unlock()
	counts := make(map[string]int)
	ids := make(map[String]bool)
	for range 2000 {
		key, id := cachedDest(fake.address(), 0)
		counts[string(key)]++
		ids[id] = true
		if !signedHexID.MatchString(string(id)) {
			t.Fatalf("bad rotating id: %q", id)
		}
	}
	if len(counts) != 8 || len(ids) < 1900 {
		t.Fatalf("keys=%d ids=%d", len(counts), len(ids))
	}
	for _, key := range keys[2:] {
		if n := counts[string(key)]; n < 150 || n > 350 {
			t.Fatalf("nonuniform key selection: %d/2000", n)
		}
	}
}

func TestDestCacheSeparatesProtocolVersions(t *testing.T) {
	key := testPublicKey(t)
	fake := newFakeDest(t, func(conn net.Conn, reader io.Reader) {
		packet, err := readPacket(reader)
		if err != nil {
			return
		}
		var version Varint
		if packet.readFields(&version) != nil {
			return
		}
		if _, err := readPacket(reader); err != nil {
			return
		}
		id, public, token := String(fmt.Sprint(version)), Bytes(key), Bytes{1, 2, 3, 4}
		_ = writePacket(conn, 1, &id, &public, &token)
	})
	for _, version := range []uint32{775, 776} {
		entry := newDestEntry()
		entry.sampleDelay = 5 * time.Millisecond
		installDestEntry(fake.address(), version, entry)
		PrepareDest(fake.address(), version)
	}
	for _, version := range []uint32{775, 776} {
		waitDest(t, fake.address(), version)
		_, id := cachedDest(fake.address(), version)
		if id != String(fmt.Sprint(version)) {
			t.Fatalf("version %d got %q", version, id)
		}
	}
	if destKey(fake.address(), 0) != destKey(fake.address(), 775) {
		t.Fatal("default version not canonicalized")
	}
}

func TestDestCacheExpiresAfter24HoursWithoutUse(t *testing.T) {
	fake := onlineDest(t, 1)
	entry := newDestEntry()
	now := time.Unix(1800000000, 0)
	entry.now = func() time.Time { return now }
	entry.sampleDelay = time.Millisecond
	installDestEntry(fake.address(), 0, entry)
	PrepareDest(fake.address(), 0)
	waitDest(t, fake.address())
	entry.mu.Lock()
	now = now.Add(23 * time.Hour)
	entry.next = now.Add(time.Hour)
	entry.mu.Unlock()
	cachedDest(fake.address(), 0)
	entry.mu.Lock()
	lastUse := entry.lastUse
	now = now.Add(24*time.Hour - time.Nanosecond)
	entry.next = now.Add(time.Hour)
	entry.mu.Unlock()
	refreshDest(destKey(fake.address(), 0), entry, false)
	if _, ok := destKeys.Load(destKey(fake.address(), 0)); !ok {
		t.Fatal("cache expired before 24h")
	}
	entry.mu.Lock()
	if entry.lastUse != lastUse {
		t.Error("timer refreshed last use")
	}
	now = now.Add(time.Nanosecond)
	entry.mu.Unlock()
	refreshDest(destKey(fake.address(), 0), entry, false)
	if _, ok := destKeys.Load(destKey(fake.address(), 0)); ok {
		t.Fatal("unused entry retained after 24h")
	}
	entry.mu.Lock()
	if !entry.retired || entry.timer != nil {
		t.Error("expired timer not stopped")
	}
	entry.mu.Unlock()
}

func TestDestCacheExpiryDuringProbe(t *testing.T) {
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	key := testPublicKey(t)
	fake := newFakeDest(t, func(conn net.Conn, reader io.Reader) {
		if _, err := readPacket(reader); err != nil {
			return
		}
		if _, err := readPacket(reader); err != nil {
			return
		}
		<-release
		id, public, token := String("0"), Bytes(key), Bytes{1, 2, 3, 4}
		_ = writePacket(conn, 1, &id, &public, &token)
	})
	entry := newDestEntry()
	entry.sampleDelay = time.Millisecond
	entry.retention = 50 * time.Millisecond
	installDestEntry(fake.address(), 0, entry)
	PrepareDest(fake.address(), 0)
	eventually(t, func() bool { return len(fake.snapshots()) == 1 })
	eventually(t, func() bool { _, ok := destKeys.Load(destKey(fake.address(), 0)); return !ok })
	close(release)
	eventually(t, func() bool { entry.mu.Lock(); defer entry.mu.Unlock(); return !entry.probing })
	entry.mu.Lock()
	if entry.timer != nil || !entry.retired {
		t.Error("expired in-flight probe rearmed timer")
	}
	entry.mu.Unlock()
	if len(fake.snapshots()) != 1 {
		t.Fatal("expired probe took second sample")
	}
}

func TestDestCacheTimerStopsAndFreshUseRestarts(t *testing.T) {
	fake := onlineDest(t, 1)
	entry := newDestEntry()
	entry.sampleDelay = time.Millisecond
	entry.refresh = 20 * time.Millisecond
	entry.retention = 100 * time.Millisecond
	installDestEntry(fake.address(), 0, entry)
	PrepareDest(fake.address(), 0)
	waitDest(t, fake.address())
	eventually(t, func() bool { _, ok := destKeys.Load(destKey(fake.address(), 0)); return !ok })
	entry.mu.Lock()
	if !entry.retired || entry.timer != nil || entry.probing {
		t.Error("retired entry still active")
	}
	entry.mu.Unlock()
	count := len(fake.snapshots())
	time.Sleep(80 * time.Millisecond)
	if len(fake.snapshots()) != count {
		t.Fatal("expired cache kept probing")
	}
	PrepareDest(fake.address(), 0)
	replacement := waitDest(t, fake.address())
	if replacement == entry {
		t.Fatal("fresh use resurrected retired entry")
	}
	if len(fake.snapshots()) != count+2 {
		t.Fatal("fresh use did not restart paired probes")
	}
}
