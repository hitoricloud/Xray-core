package hmc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/log"
)

var fallbackTime = time.Unix(1800000015, 0)

type destRecord struct {
	mu   sync.Mutex
	data []byte
}

func (r *destRecord) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data = append(r.data, p...)
	return len(p), nil
}

func (r *destRecord) snapshot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.data)
}

type fakeDest struct {
	listener    net.Listener
	mu          sync.Mutex
	records     []*destRecord
	connections []net.Conn
	wg          sync.WaitGroup
	key         []byte
}

func newFakeDest(t *testing.T, serve func(net.Conn, io.Reader)) *fakeDest {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDest{listener: listener}
	acceptDone := make(chan struct{})
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			record := new(destRecord)
			f.mu.Lock()
			f.connections = append(f.connections, conn)
			f.records = append(f.records, record)
			f.mu.Unlock()
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				serve(conn, io.TeeReader(conn, record))
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-acceptDone
		f.mu.Lock()
		for _, conn := range f.connections {
			conn.Close()
		}
		f.mu.Unlock()
		f.wg.Wait()
		destKeys.Range(func(key, value any) bool {
			if key.(destCacheKey).dest == f.address() {
				entry := value.(*destEntry)
				entry.mu.Lock()
				entry.retired = true
				if entry.timer != nil {
					entry.timer.Stop()
				}
				destKeys.Delete(key)
				entry.mu.Unlock()
			}
			return true
		})
	})
	return f
}

func (f *fakeDest) address() string { return f.listener.Addr().String() }
func (f *fakeDest) snapshots() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([][]byte, len(f.records))
	for i, record := range f.records {
		result[i] = record.snapshot()
	}
	return result
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(end) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(time.Millisecond)
	}
}

func loginStartWire(t *testing.T, address String, state Varint, uuid UUID) []byte {
	t.Helper()
	var wire bytes.Buffer
	version, host, port, username := Varint(775), String(address), UnsignedShort(25565), String("test_user")
	if err := writePacket(&wire, 0, &version, &host, &port, &state); err != nil {
		t.Fatal(err)
	}
	if state == 2 {
		if err := writePacket(&wire, 0, &username, &uuid); err != nil {
			t.Fatal(err)
		}
	} else if state == 1 {
		if err := writePacket(&wire, 0); err != nil {
			t.Fatal(err)
		}
	}
	return wire.Bytes()
}

func fallbackPair(t *testing.T, dest string, cache *replayCache, limits *relayLimits, versions ...uint32) (net.Conn, *serverConn, <-chan error) {
	t.Helper()
	raw, peer := tcpPair(t)
	_ = raw.SetDeadline(time.Now().Add(4 * time.Second))
	server, err := wrapConnServer(peer, nil, testPassword, testPublicKey(t))
	if err != nil {
		t.Fatal(err)
	}
	server.dest, server.knocks, server.relayLimits = dest, cache, limits
	server.now = func() time.Time { return fallbackTime }
	if len(versions) > 0 {
		server.protocolVersion = versions[0]
	}
	done := make(chan error, 1)
	go func() { err := server.handshake(); server.Close(); done <- err }()
	t.Cleanup(func() { raw.Close(); server.Close() })
	return raw, server, done
}

func TestFallbackRelaysPreAuthByteForByte(t *testing.T) {
	window := fallbackTime.Unix() / 30
	cases := map[string][]byte{
		"status":               loginStartWire(t, "localhost", 1, UUID{}),
		"garbage":              {0xff, 0xff, 0xff, 0xff, 0xff},
		"oversized":            appendVarint(nil, preAuthPacketBodyLength+1),
		"oversized-body":       append(appendVarint(nil, 8192), bytes.Repeat([]byte{0xab}, 8192)...),
		"no-knock":             loginStartWire(t, "localhost", 2, testLoginProfile("test_user").UUID),
		"wrong-password-knock": loginStartWire(t, loginKnock(testPassword+"bad", "localhost", "test_user", testLoginProfile("test_user").UUID, window), 2, testLoginProfile("test_user").UUID),
		"stale-minus-two":      loginStartWire(t, loginKnock(testPassword, "localhost", "test_user", testLoginProfile("test_user").UUID, window-2), 2, testLoginProfile("test_user").UUID),
		"stale-plus-two":       loginStartWire(t, loginKnock(testPassword, "localhost", "test_user", testLoginProfile("test_user").UUID, window+2), 2, testLoginProfile("test_user").UUID),
		"unknown-state":        loginStartWire(t, "localhost", 7, UUID{}),
		"bad-fields":           {1, 0},
		"wrong-first-id":       {1, 7},
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			reply := []byte("genuine dest reply")
			if name == "status" {
				reply, _ = encodePacket(0, new(String(`{"description":"real fake server"}`)))
			}
			fake := newFakeDest(t, func(conn net.Conn, reader io.Reader) {
				got := make([]byte, len(wire))
				if _, err := io.ReadFull(reader, got); err == nil {
					_ = writeFull(conn, reply)
				}
			})
			cache := newReplayCache(16, 2*time.Minute)
			raw, _, done := fallbackPair(t, fake.address(), cache, nil)
			if err := writeFull(raw, wire); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(reply))
			if _, err := io.ReadFull(raw, got); err != nil || !bytes.Equal(got, reply) {
				t.Fatalf("reply=%q error=%v", got, err)
			}
			raw.Close()
			<-done
			records := fake.snapshots()
			if len(records) != 1 || !bytes.Equal(records[0], wire) {
				t.Fatalf("not an exact relay: %x != %x", records, wire)
			}
		})
	}
}

func TestKnockAdjacentWindowsAndNoPostKnockFallback(t *testing.T) {
	for _, delta := range []int64{-1, 0, 1} {
		t.Run(fmt.Sprint(delta), func(t *testing.T) {
			fake := onlineDest(t, 1)
			raw, _, done := fallbackPair(t, fake.address(), newReplayCache(16, 2*time.Minute), nil)
			knock := loginKnock(testPassword, "localhost", "test_user", testLoginProfile("test_user").UUID, fallbackTime.Unix()/30+delta)
			if err := writeFull(raw, loginStartWire(t, knock, 2, testLoginProfile("test_user").UUID)); err != nil {
				t.Fatal(err)
			}
			request, err := readPacket(raw)
			if err != nil || request.packetID != 1 {
				t.Fatalf("adjacent knock rejected: %v", err)
			}
			if err = writePacket(raw, 9); err != nil {
				t.Fatal(err)
			}
			reply, err := io.ReadAll(raw)
			if err != nil || len(reply) != 0 {
				t.Fatalf("post-knock failure not silent: %x %v", reply, err)
			}
			<-done
			eventually(t, func() bool {
				value, ok := destKeys.Load(destKey(fake.address(), 0))
				if !ok {
					return false
				}
				entry := value.(*destEntry)
				entry.mu.Lock()
				defer entry.mu.Unlock()
				return !entry.probing
			})
			if len(fake.snapshots()) != 2 {
				t.Fatalf("valid knock relayed; records=%d", len(fake.snapshots()))
			}
		})
	}
}

func TestFallbackDestDown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dest := listener.Addr().String()
	listener.Close()
	raw, _, done := fallbackPair(t, dest, newReplayCache(16, time.Minute), nil)
	if err := writeFull(raw, []byte{1, 9}); err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(raw); len(got) != 0 {
		t.Fatalf("reply=%x", got)
	}
	<-done
}

func TestFallbackLimitsAndNoGoroutineLeak(t *testing.T) {
	baseline := runtime.NumGoroutine()
	for _, mode := range []string{"upload", "download", "idle", "total", "slots", "half-close"} {
		t.Run(mode, func(t *testing.T) {
			limits := relayLimits{30 * time.Millisecond, time.Second, 16, 16, make(chan struct{}, 1)}
			if mode == "total" {
				limits.idle, limits.total = time.Second, 30*time.Millisecond
			}
			if mode == "slots" {
				limits.slots <- struct{}{}
			}
			fake := newFakeDest(t, func(conn net.Conn, reader io.Reader) {
				if mode == "download" {
					_ = writeFull(conn, bytes.Repeat([]byte("x"), 100))
					return
				}
				got, _ := io.ReadAll(reader)
				if mode == "half-close" && string(got) == "request" {
					_ = writeFull(conn, []byte("response"))
				}
			})
			raw, peer := tcpPair(t)
			done := make(chan struct{})
			started := time.Now()
			go func() { relayDest(peer, fake.address(), nil, limits); peer.Close(); close(done) }()
			if mode == "upload" {
				_ = writeFull(raw, bytes.Repeat([]byte("x"), 100))
			}
			if mode == "half-close" {
				_ = writeFull(raw, []byte("request"))
				_ = raw.(*net.TCPConn).CloseWrite()
			}
			_ = raw.SetReadDeadline(time.Now().Add(time.Second))
			got, _ := io.ReadAll(raw)
			raw.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("relay did not stop")
			}
			if (mode == "idle" || mode == "total") && time.Since(started) > 500*time.Millisecond {
				t.Fatalf("%s deadline was not enforced promptly", mode)
			}
			if mode == "upload" {
				eventually(t, func() bool { records := fake.snapshots(); return len(records) == 1 && len(records[0]) == 16 })
			}
			records := fake.snapshots()
			if mode == "slots" && len(records) != 0 {
				t.Fatal("concurrency cap bypassed")
			}
			if mode == "download" && len(got) != 16 {
				t.Fatalf("download bytes=%d", len(got))
			}
			if mode == "upload" && (len(records) != 1 || len(records[0]) > 16) {
				t.Fatalf("upload cap: %v", records)
			}
			if mode == "half-close" && string(got) != "response" {
				t.Fatalf("half-close response: %q", got)
			}
		})
	}
	eventually(t, func() bool { return runtime.NumGoroutine() <= baseline+1 })
}

func onlineDest(t *testing.T, firstID int) *fakeDest {
	private, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeDest(t, func(conn net.Conn, reader io.Reader) {
		handshake, err := readPacket(reader)
		if err != nil {
			return
		}
		var version, state Varint
		var host String
		var port UnsignedShort
		if handshake.readFields(&version, &host, &port, &state) != nil {
			return
		}
		if _, err = readPacket(reader); err != nil {
			return
		}
		if state == 1 {
			_ = writePacket(conn, 0, new(String(`{"description":"fake online server"}`)))
			return
		}
		if firstID != 1 {
			_ = writePacket(conn, firstID, new(Varint(256)))
			return
		}
		id, public, token, auth := String("dest-id"), Bytes(key), Bytes{1, 2, 3, 4}, Boolean(true)
		_ = writePacket(conn, 1, &id, &public, &token, &auth)
	})
	fake.key = key
	return fake
}

func waitDest(t *testing.T, dest string, versions ...uint32) *destEntry {
	t.Helper()
	version := uint32(0)
	if len(versions) > 0 {
		version = versions[0]
	}
	var entry *destEntry
	eventually(t, func() bool {
		value, ok := destKeys.Load(destKey(dest, version))
		if !ok {
			return false
		}
		entry = value.(*destEntry)
		entry.mu.Lock()
		defer entry.mu.Unlock()
		return !entry.probing
	})
	return entry
}

func TestDestProbeDoesNotBlockHandshake(t *testing.T) {
	release := make(chan struct{})
	key := testPublicKey(t)
	fake := newFakeDest(t, func(conn net.Conn, reader io.Reader) {
		if _, err := readPacket(reader); err != nil {
			return
		}
		if _, err := readPacket(reader); err != nil {
			return
		}
		<-release
		id, public, token := String(""), Bytes(key), Bytes{1, 2, 3, 4}
		_ = writePacket(conn, 1, &id, &public, &token)
	})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	raw, server, done := fallbackPair(t, fake.address(), newReplayCache(16, time.Minute), nil)
	knock := loginKnock(testPassword, "localhost", "test_user", testLoginProfile("test_user").UUID, fallbackTime.Unix()/30)
	started := time.Now()
	if err := writeFull(raw, loginStartWire(t, knock, 2, testLoginProfile("test_user").UUID)); err != nil {
		t.Fatal(err)
	}
	request, err := readPacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("login waited for dest probe")
	}
	var id String
	var public, token Bytes
	if err := request.readFields(&id, &public, &token); err != nil || !bytes.Equal(public, server.publicKey) {
		t.Fatalf("missing camouflage key during probe: %v", err)
	}
	raw.Close()
	<-done
	close(release)
	waitDest(t, fake.address())
}

func TestDestProbeCacheAndPublishedKey(t *testing.T) {
	fake := onlineDest(t, 1)
	PrepareDest(fake.address(), 776)
	entry := waitDest(t, fake.address(), 776)
	entry.mu.Lock()
	key, id := bytes.Clone(entry.keys[0]), entry.serverIDs[0]
	if time.Until(entry.next) < 59*time.Minute {
		t.Error("successful probe must refresh hourly")
	}
	entry.mu.Unlock()
	if !bytes.Equal(key, fake.key) || id != "dest-id" {
		t.Fatal("dest key not cached")
	}
	snapshots := fake.snapshots()
	if len(snapshots) != 2 {
		t.Fatal("expected two initial probe samples")
	}
	reader := bytes.NewReader(snapshots[0])
	handshake, err := readPacket(reader)
	if err != nil {
		t.Fatal(err)
	}
	var version, state Varint
	var host String
	var port UnsignedShort
	if err := handshake.readFields(&version, &host, &port, &state); err != nil || version != 776 || host != "127.0.0.1" || state != 2 {
		t.Fatalf("probe handshake: %v %d %s", err, version, host)
	}
	start, err := readPacket(reader)
	if err != nil {
		t.Fatal(err)
	}
	var name String
	var uuid UUID
	if err := start.readFields(&name, &uuid); err != nil || len(name) != 9 || !strings.HasPrefix(string(name), "Hm") {
		t.Fatalf("probe login: %v %s", err, name)
	}
	raw, _, done := fallbackPair(t, fake.address(), newReplayCache(16, time.Minute), nil, 776)
	knock := loginKnock(testPassword, "localhost", "test_user", testLoginProfile("test_user").UUID, fallbackTime.Unix()/30)
	if err := writeFull(raw, loginStartWire(t, knock, 2, testLoginProfile("test_user").UUID)); err != nil {
		t.Fatal(err)
	}
	request, err := readPacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	var gotID String
	var public, token Bytes
	if err := request.readFields(&gotID, &public, &token); err != nil || gotID != id || !bytes.Equal(public, key) {
		t.Fatalf("wrong published dest key: %v", err)
	}
	raw.Close()
	<-done
	if len(fake.snapshots()) != 2 {
		t.Fatal("valid knock relayed or duplicate probe")
	}
}

type warningCapture struct{ messages chan string }

func (w warningCapture) Handle(message log.Message) {
	select {
	case w.messages <- message.String():
	default:
	}
}

func TestDestProbeOfflineWarningOnceAndRetry(t *testing.T) {
	messages := make(chan string, 8)
	log.RegisterHandler(warningCapture{messages})
	defer log.RegisterHandler(warningCapture{make(chan string, 1)})
	fake := onlineDest(t, 3)
	PrepareDest(fake.address(), 0)
	entry := waitDest(t, fake.address())
	select {
	case message := <-messages:
		if !strings.Contains(message, "not online-mode") {
			t.Fatal(message)
		}
	case <-time.After(time.Second):
		t.Fatal("missing offline warning")
	}
	entry.mu.Lock()
	if entry.keys != nil || !entry.warned || time.Until(entry.next) > time.Minute {
		t.Error("offline cache state")
	}
	entry.next = time.Time{}
	entry.timer.Stop()
	entry.mu.Unlock()
	PrepareDest(fake.address(), 0)
	waitDest(t, fake.address())
	select {
	case message := <-messages:
		t.Fatalf("duplicate warning: %s", message)
	case <-time.After(20 * time.Millisecond):
	}
	if len(fake.snapshots()) != 2 {
		t.Fatal("failed dest did not retry")
	}
}

func TestKnockReplayAfterAcceptedConnection(t *testing.T) {
	fake := onlineDest(t, 1)
	PrepareDest(fake.address(), 0)
	waitDest(t, fake.address())
	cache := newReplayCache(16, 2*time.Minute)
	knock := loginKnock(testPassword, "localhost", "test_user", testLoginProfile("test_user").UUID, fallbackTime.Unix()/30)
	a := beginKnockAttempt(t, fake.address(), cache, knock)
	garbage := Bytes(make([]byte, len(a.secret)))
	if err := writePacket(a.raw, 1, &garbage, &garbage); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(a.raw); err != nil || len(got) != 0 {
		t.Fatalf("A not silent: %x %v", got, err)
	}
	<-a.done
	b := beginKnockAttempt(t, fake.address(), cache, knock)
	if !b.finish(t) {
		t.Fatal("garbage proof burned legitimate admission")
	}
	// The knock is consumed now: a replay is relayed like any outsider and the dest answers it.
	raw, _, _ := fallbackPair(t, fake.address(), cache, nil)
	if err := writeFull(raw, loginStartWire(t, knock, 2, testLoginProfile("test_user").UUID)); err != nil {
		t.Fatal(err)
	}
	reply, err := readPacket(raw)
	if err != nil || reply.packetID != 1 {
		t.Fatalf("replayed knock must receive the dest's own Encryption Request: %v", err)
	}
	eventually(t, func() bool { return len(fake.snapshots()) == 3 })
	if !bytes.Contains(fake.snapshots()[2], []byte(knock)) {
		t.Fatal("dest did not receive the replayed handshake byte for byte")
	}
	raw.Close()
}

func TestKnockFormulaAndCachePoisoning(t *testing.T) {
	now := fallbackTime
	uuid := testLoginProfile("test_user").UUID
	knock := loginKnock(testPassword, "localhost", "test_user", uuid, now.Unix()/30)
	for _, delta := range []int64{-2, -1, 0, 1, 2} {
		candidate := loginKnock(testPassword, "localhost", "test_user", uuid, now.Unix()/30+delta)
		if validKnock(testPassword, candidate, "test_user", uuid, now) != (delta >= -1 && delta <= 1) {
			t.Fatalf("window %d", delta)
		}
	}
	raw, server, done := fallbackPair(t, "", newReplayCache(16, 2*time.Minute), nil)
	if err := writeFull(raw, loginStartWire(t, String("wrong-host")+knock[len("localhost"):], 2, uuid)); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(raw); err != nil || len(got) != 0 {
		t.Fatalf("bad knock not silent: %x %v", got, err)
	}
	<-done
	if len(server.knocks.seen) != 0 {
		t.Fatal("invalid HMAC poisoned knock cache")
	}
	if !server.knocks.firstUse(knockToken(knock), now) || server.knocks.firstUse(knockToken(knock), now) {
		t.Fatal("deterministic repeat must be a replay")
	}
}

func TestPostKnockServerNeedsNoProfiles(t *testing.T) {
	fake := onlineDest(t, 1)
	PrepareDest(fake.address(), 0)
	waitDest(t, fake.address())
	cache := newReplayCache(16, time.Minute)
	knock := loginKnock(testPassword, "localhost", "test_user", testLoginProfile("test_user").UUID, fallbackTime.Unix()/30)
	attempt := beginKnockAttempt(t, fake.address(), cache, knock)
	if !attempt.finish(t) {
		t.Fatal("server rejected authenticated account without a profile list")
	}
	if len(fake.snapshots()) != 2 {
		t.Fatal("MAC-valid knock was relayed")
	}
}

func TestRSAFallbackFields(t *testing.T) {
	secret, proof, _, err := newLoginResponse(testPassword, []byte("binding"), []byte{1, 2, 3, 4}, []byte("invalid SPKI"))
	if err != nil || len(secret) != 128 || len(proof) != 128 || secret[0]&128 != 0 || proof[0]&128 != 0 {
		t.Fatalf("bad fallback fields: %v", err)
	}
	if _, err := verifyLoginResponse(testPassword, []byte("binding"), []byte{1, 2, 3, 4}, secret, proof, []byte("invalid SPKI")); err != nil {
		t.Fatal(err)
	}
}

func TestRSAFieldsBelowModulusAndProof(t *testing.T) {
	key := parseRSA(testPublicKey(t))
	key.N = new(big.Int).Lsh(big.NewInt(3), 1022)
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	high, highProof := 0, 0
	for range 512 {
		secret, proof, keys, err := newLoginResponse(testPassword, []byte("binding"), []byte{1, 2, 3, 4}, der)
		if err != nil {
			t.Fatal(err)
		}
		if len(secret) != key.Size() || len(proof) != key.Size() || new(big.Int).SetBytes(secret).Cmp(key.N) >= 0 || new(big.Int).SetBytes(proof).Cmp(key.N) >= 0 {
			t.Fatal("field outside modulus")
		}
		if secret[0]&0x80 != 0 {
			high++
		}
		if proof[0]&0x80 != 0 {
			highProof++
		}
		verified, err := verifyLoginResponse(testPassword, []byte("binding"), []byte{1, 2, 3, 4}, secret, proof, der)
		if err != nil || *verified != *keys {
			t.Fatalf("proof failed: %v", err)
		}
	}
	if high < 100 || high > 250 || highProof < 100 || highProof > 250 {
		t.Fatalf("implausible high-bit frequency: secret=%d proof=%d /512", high, highProof)
	}
	for _, bits := range []uint{2048, 4096, 8192} {
		key.N = new(big.Int).Lsh(big.NewInt(3), bits-2)
		der, _ = x509.MarshalPKIXPublicKey(key)
		secret, proof, _, err := newLoginResponse(testPassword, []byte("binding"), []byte{1, 2, 3, 4}, der)
		if err != nil || len(secret) != int(bits/8) {
			t.Fatalf("RSA-%d: %v", bits, err)
		}
		if _, err := verifyLoginResponse(testPassword, []byte("binding"), []byte{1, 2, 3, 4}, secret, proof, der); err != nil {
			t.Fatal(err)
		}
		var wire bytes.Buffer
		s, p := Bytes(secret), Bytes(proof)
		if err := writePacket(&wire, 1, &s, &p); err != nil {
			t.Fatal(err)
		}
		packet, err := readPacket(&wire)
		if err != nil {
			t.Fatal(err)
		}
		var decodedSecret, decodedProof Bytes
		if err := packet.readFields(&decodedSecret, &decodedProof); err != nil || !bytes.Equal(decodedSecret, secret) || !bytes.Equal(decodedProof, proof) {
			t.Fatalf("RSA-%d fields did not round-trip: %v", bits, err)
		}
	}
}
