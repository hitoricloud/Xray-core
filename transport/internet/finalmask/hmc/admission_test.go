package hmc

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/log"
	"google.golang.org/protobuf/proto"
)

func testAdmission(t testing.TB, pre, perIP, rate, burst uint32) *admissionLimiter {
	t.Helper()
	p := (&Config{MaxPreAuth: pre, MaxPreAuthPerIp: perIP, RatePerIp: rate, BurstPerIp: burst}).admissionPolicy()
	return newAdmissionLimiter(p, 16, func() time.Time { return fallbackTime })
}

func admissionCount(a *admissionLimiter) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pre
}

func TestAdmissionGlobalAndSourceCaps(t *testing.T) {
	a := testAdmission(t, 4, 2, 100, 100)
	one, two := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")
	l1, l2 := a.acquire(one), a.acquire(one)
	if l1 == nil || l2 == nil || a.acquire(one) != nil {
		t.Fatal("per-IP cap not enforced")
	}
	l3 := a.acquire(two)
	if l3 == nil || a.acquire(two) != nil {
		t.Fatal("global cap not enforced")
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() { l1.release() })
	}
	wg.Wait()
	if admissionCount(a) != 2 {
		t.Fatal("release was not exactly once")
	}
	l4 := a.acquire(two)
	if l4 == nil {
		t.Fatal("released slot not reusable")
	}
	l2.release()
	l3.release()
	l4.release()
	if admissionCount(a) != 0 || len(a.preIP) != 0 {
		t.Fatal("slots leaked")
	}
}

func TestAdmissionIPv6AndUnknownGrouping(t *testing.T) {
	cases := []struct {
		addr net.Addr
		want string
	}{
		{&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::1"), Port: 1}, "2001:db8:1:2::"},
		{&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:ffff::2"), Port: 99}, "2001:db8:1:2::"},
		{&net.TCPAddr{IP: net.ParseIP("2001:db8:1:3::1")}, "2001:db8:1:3::"},
		{&net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: 1}, "127.0.0.1"},
		{&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 99}, "127.0.0.1"},
		{&net.UnixAddr{Name: "/tmp/one", Net: "unix"}, "invalid IP"},
		{&net.UnixAddr{Name: "/tmp/two", Net: "unix"}, "invalid IP"},
		{nil, "invalid IP"},
	}
	for _, c := range cases {
		if got := admissionSource(c.addr).String(); got != c.want {
			t.Fatalf("%v: %s != %s", c.addr, got, c.want)
		}
	}
	a := testAdmission(t, 10, 1, 100, 100)
	first := a.acquire(admissionSource(cases[0].addr))
	if first == nil || a.acquire(admissionSource(cases[1].addr)) != nil {
		t.Fatal("IPv6 /64 cap bypassed")
	}
	second := a.acquire(admissionSource(cases[2].addr))
	if second == nil {
		t.Fatal("different /64 rejected")
	}
	unknown := a.acquire(admissionSource(cases[5].addr))
	if unknown == nil || a.acquire(admissionSource(nil)) != nil {
		t.Fatal("unknown bucket not shared")
	}
	first.release()
	second.release()
	unknown.release()
}

func TestAdmissionRateBurstRefill(t *testing.T) {
	a := testAdmission(t, 10, 10, 2, 3)
	now := fallbackTime
	a.now = func() time.Time { return now }
	ip := netip.MustParseAddr("127.0.0.1")
	accept := func(want bool) {
		t.Helper()
		l := a.acquire(ip)
		if (l != nil) != want {
			t.Fatalf("admitted=%t want=%t", l != nil, want)
		}
		l.release()
	}
	for range 3 {
		accept(true)
	}
	accept(false)
	other := a.acquire(netip.MustParseAddr("127.0.0.2"))
	if other == nil {
		t.Fatal("one source exhausted another's bucket")
	}
	other.release()
	now = now.Add(250 * time.Millisecond)
	accept(false)
	now = now.Add(250 * time.Millisecond)
	accept(true)
	accept(false)
	now = now.Add(time.Hour)
	for range 3 {
		accept(true)
	}
	accept(false)
}

func TestAdmissionRateLRUExpiryAndBoundedMemory(t *testing.T) {
	a := testAdmission(t, 3, 1, 1, 1)
	a.capacity = 7
	now := fallbackTime
	a.now = func() time.Time { return now }
	first := netip.AddrFrom4([4]byte{10, 0, 0, 0})
	for i := range 7 {
		l := a.acquire(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}))
		if l == nil {
			t.Fatal("initial acquire")
		}
		l.release()
	}
	if a.acquire(first) != nil {
		t.Fatal("hot exhausted bucket reset")
	}
	l := a.acquire(netip.MustParseAddr("10.0.1.0"))
	l.release()
	if _, ok := a.buckets[first]; !ok {
		t.Fatal("recent bucket evicted")
	}
	if _, ok := a.buckets[netip.MustParseAddr("10.0.0.1")]; ok {
		t.Fatal("LRU bucket retained")
	}
	now = now.Add(time.Second)
	held := a.acquire(first)
	if held == nil {
		t.Fatal("could not hold active source")
	}
	defer held.release()
	for i := range 200000 {
		ip := netip.AddrFrom4([4]byte{11, byte(i >> 16), byte(i >> 8), byte(i)})
		l := a.acquire(ip)
		if l == nil {
			t.Fatalf("source %d rejected", i)
		}
		l.release()
		if len(a.buckets) > 7 || a.lru.Len() > 7 {
			t.Fatal("unbounded source memory")
		}
	}
	if a.acquire(first) != nil {
		t.Fatal("LRU eviction reset active source cap")
	}
	now = now.Add(admissionIdle)
	if a.acquire(first) != nil {
		t.Fatal("expiry reset active source cap")
	}
	held.release()
	if len(a.buckets) != 1 || a.lru.Len() != 1 {
		t.Fatal("idle sources did not expire")
	}
	if len(a.preIP) != 0 {
		t.Fatal("active source map leaked")
	}
}

type admissionConn struct {
	net.Conn
	remote net.Addr
	reads  atomic.Int64
}

func (c *admissionConn) RemoteAddr() net.Addr       { return c.remote }
func (c *admissionConn) Read(p []byte) (int, error) { c.reads.Add(1); return c.Conn.Read(p) }

func admissionConfig(t testing.TB) *Config {
	t.Helper()
	c := &Config{Password: testPassword, CamouflagePublicKey: testPublicKey(t), MaxPreAuth: 8, MaxPreAuthPerIp: 1, RatePerIp: 1000000, BurstPerIp: 1000000}
	admissionPolicies.Delete(c.admissionPolicy())
	t.Cleanup(func() { admissionPolicies.Delete(c.admissionPolicy()) })
	return c
}

func TestAdmissionWrapRejectsBeforeReadEvenWithDest(t *testing.T) {
	c := admissionConfig(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	first, err := c.WrapConnServer(a)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	go first.(*serverConn).handshake()
	eventually(t, func() bool { return admissionCount(c.admission()) == 1 })
	var held []*admissionLease
	for i := 0; i < 5; i++ {
		l := c.admission().acquire(netip.AddrFrom4([4]byte{10, byte(i), 0, 1}))
		if l == nil {
			t.Fatal("global-cap fixture rejected")
		}
		held = append(held, l)
		defer l.release()
	}
	c.Dest = "127.0.0.1:1"
	x, y := net.Pipe()
	defer x.Close()
	defer y.Close()
	raw := &admissionConn{Conn: x, remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	second, err := c.WrapConnServer(raw)
	if err != nil {
		t.Fatalf("a rejection must never surface from Accept-time wrapping: %v", err)
	}
	if err := second.(*serverConn).handshake(); !errors.Is(err, errAdmissionRejected) {
		t.Fatalf("overload accepted: %v", err)
	}
	if raw.reads.Load() != 0 {
		t.Fatal("rejected connection was read")
	}
	if _, err := y.Write([]byte{1}); err == nil {
		t.Fatal("rejected connection not closed")
	}
	if admissionCount(c.admission()) != 6 {
		t.Fatal("rejection changed slot count")
	}
}

func TestAdmissionRateRejectsBeforeRead(t *testing.T) {
	c := admissionConfig(t)
	c.RatePerIp, c.BurstPerIp = 1, 1
	a := c.admission()
	now := time.Now()
	a.now = func() time.Time { return now }
	x, y := net.Pipe()
	defer y.Close()
	first, err := c.WrapConnServer(x)
	if err != nil {
		t.Fatal(err)
	}
	go first.(*serverConn).handshake()
	eventually(t, func() bool { return admissionCount(a) == 1 })
	first.Close()
	eventually(t, func() bool { return admissionCount(a) == 0 })
	c.Dest = "127.0.0.1:1"
	x, z := net.Pipe()
	defer x.Close()
	defer z.Close()
	raw := &admissionConn{Conn: x}
	second, err := c.WrapConnServer(raw)
	if err != nil {
		t.Fatalf("a rejection must never surface from Accept-time wrapping: %v", err)
	}
	if err := second.(*serverConn).handshake(); !errors.Is(err, errAdmissionRejected) {
		t.Fatalf("exhausted rate bucket accepted: %v", err)
	}
	if raw.reads.Load() != 0 || admissionCount(a) != 0 {
		t.Fatal("rate rejection read bytes or retained a slot")
	}
	if _, err := z.Write([]byte{1}); err == nil {
		t.Fatal("rate rejection did not close")
	}
}

func TestAdmissionLifecycleRelease(t *testing.T) {
	for _, mode := range []string{"success", "failure", "close", "concurrent-close", "timeout", "constructor-failure", "deadline-failure"} {
		t.Run(mode, func(t *testing.T) {
			c := admissionConfig(t)
			raw, peer := tcpPair(t)
			defer raw.Close()
			defer peer.Close()
			_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
			var transport net.Conn = peer
			if mode == "constructor-failure" {
				c.CamouflagePublicKey = nil
			}
			if mode == "deadline-failure" {
				transport = &admissionDeadlineFailure{Conn: peer}
			}
			wrapped, err := c.WrapConnServer(transport)
			if mode == "constructor-failure" || mode == "deadline-failure" {
				if err == nil || admissionCount(c.admission()) != 0 {
					t.Fatal("constructor leaked admission")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			server := wrapped.(*serverConn)
			defer server.Close()
			if admissionCount(c.admission()) != 0 {
				t.Fatal("slot held before the handshake started")
			}
			done := make(chan error, 1)
			go func() { done <- server.handshake() }()
			eventually(t, func() bool { return admissionCount(c.admission()) == 1 })
			if mode == "close" {
				server.Close()
				server.Close()
				<-done
			} else {
				switch mode {
				case "success":
					client, err := newClientConn(raw, []loginProfile{testLoginProfile("limit_user")}, c.Password, "localhost")
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					if err = client.handshake(); err != nil {
						t.Fatal(err)
					}
					if err = client.validateLogin(); err != nil {
						t.Fatal(err)
					}
				case "failure":
					if err := writeFull(raw, []byte{1, 9}); err != nil {
						t.Fatal(err)
					}
				case "timeout":
					if err := server.SetDeadline(time.Now().Add(time.Millisecond)); err != nil {
						t.Fatal(err)
					}
				case "concurrent-close":
					var wg sync.WaitGroup
					for range 32 {
						wg.Go(func() { server.Close() })
					}
					wg.Wait()
				}
				err = <-done
				if (err == nil) != (mode == "success") {
					t.Fatalf("handshake %s: %v", mode, err)
				}
			}
			if admissionCount(c.admission()) != 0 {
				t.Fatal("handshake or Close retained slot")
			}
			x, y := net.Pipe()
			defer x.Close()
			defer y.Close()
			next, err := c.WrapConnServer(x)
			if err != nil {
				t.Fatalf("wrapping failed: %v", err)
			}
			go next.(*serverConn).handshake()
			eventually(t, func() bool { return admissionCount(c.admission()) == 1 })
			server.Close()
			server.Close()
			if admissionCount(c.admission()) != 1 {
				t.Fatal("double release stole next slot")
			}
			next.Close()
			if admissionCount(c.admission()) != 0 {
				t.Fatal("slot leak")
			}
		})
	}
}

type admissionDeadlineFailure struct{ net.Conn }

func (*admissionDeadlineFailure) SetReadDeadline(time.Time) error { return net.ErrClosed }

func TestAdmissionConfigDefaultsValidationIsolation(t *testing.T) {
	c := admissionConfig(t)
	zero := (&Config{}).admissionPolicy()
	if zero.pre != 2048 || zero.preIP != 64 || zero.relayIP != 16 || zero.rate != 30 || zero.burst != 60 {
		t.Fatalf("defaults: %+v", zero)
	}
	copy := proto.Clone(c).(*Config)
	if c.admission() != copy.admission() {
		t.Fatal("identical policy/password not process-wide")
	}
	copy.MaxPreAuth = 16
	otherPolicy := copy.admissionPolicy()
	t.Cleanup(func() { admissionPolicies.Delete(otherPolicy) })
	if c.admission() == copy.admission() {
		t.Fatal("different inbound settings share state")
	}
	ip := netip.MustParseAddr("127.0.0.1")
	l := c.admission().acquire(ip)
	defer l.release()
	other := copy.admission().acquire(ip)
	if other == nil {
		t.Fatal("one inbound consumed another's cap")
	}
	other.release()
	copy.Password += "different"
	t.Cleanup(func() { admissionPolicies.Delete(copy.admissionPolicy()) })
	if c.admission() == copy.admission() {
		t.Fatal("different passwords share state")
	}
	for field := range 5 {
		bad := proto.Clone(c).(*Config)
		values := []*uint32{&bad.MaxPreAuth, &bad.MaxPreAuthPerIp, &bad.MaxRelaysPerIp, &bad.RatePerIp, &bad.BurstPerIp}
		*values[field] = MaxAdmissionLimit + 1
		if bad.ValidateAdmission() == nil {
			t.Fatalf("invalid field %d accepted", field)
		}
		if _, err := bad.WrapConnServer(nil); err == nil {
			t.Fatal("protobuf bypassed validation")
		}
		*values[field] = MaxAdmissionLimit
		if err := bad.ValidateAdmission(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAdmissionRelaySourceCapAndPreAuthRelease(t *testing.T) {
	c := admissionConfig(t)
	c.MaxPreAuth, c.MaxPreAuthPerIp, c.MaxRelaysPerIp = 8, 8, 1
	a := c.admission()
	defer admissionPolicies.Delete(c.admissionPolicy())
	fake := newFakeDest(t, func(conn net.Conn, r io.Reader) { _, _ = io.Copy(io.Discard, r) })
	var servers []*serverConn
	var raws []net.Conn
	var done []chan error
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			for _, raw := range raws {
				raw.Close()
			}
			for _, s := range servers {
				s.Close()
			}
			for _, d := range done {
				<-d
			}
		})
	}
	defer cleanup()
	for i, source := range []string{"127.0.0.1", "127.0.0.1", "127.0.0.2"} {
		raw, peer := tcpPair(t)
		wrapped, err := c.WrapConnServer(&admissionConn{Conn: peer, remote: &net.TCPAddr{IP: net.ParseIP(source)}})
		if err != nil {
			t.Fatal(err)
		}
		s := wrapped.(*serverConn)
		s.dest = fake.address()
		servers = append(servers, s)
		raws = append(raws, raw)
		d := make(chan error, 1)
		done = append(done, d)
		go func() { d <- s.handshake() }()
		if err := writeFull(raw, []byte{1, 9}); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			_ = raw.SetReadDeadline(time.Now().Add(time.Second))
			if n, err := raw.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatalf("relay cap not immediate close: %d %v", n, err)
			}
		} else {
			eventually(t, func() bool { return len(fake.snapshots()) == i/2+1 })
		}
		if admissionCount(a) != 0 {
			t.Fatal("fallback retained pre-auth slot")
		}
	}
	if len(fake.snapshots()) != 2 {
		t.Fatal("excess relay dialed dest or other source blocked")
	}
	cleanup()
	if len(a.relays) != 0 {
		t.Fatal("relay source slots leaked")
	}
}

func TestAdmissionRelayGlobalRejectionReleasesSourceSlot(t *testing.T) {
	a := testAdmission(t, 2, 1, 1, 1)
	lease := a.acquire(netip.MustParseAddr("127.0.0.1"))
	lease.release()
	limits := fallbackLimits
	limits.slots = make(chan struct{})
	x, y := net.Pipe()
	defer x.Close()
	defer y.Close()
	lease.relay(x, "127.0.0.1:1", nil, limits)
	if len(a.relays) != 0 {
		t.Fatal("global rejection leaked source slot")
	}
}

func TestAdmissionWarningAggregatedAndRateLimited(t *testing.T) {
	messages := make(chan string, 8)
	log.RegisterHandler(warningCapture{messages})
	defer log.RegisterHandler(warningCapture{make(chan string, 1)})
	w := new(admissionWarning)
	now := fallbackTime
	w.reject(now)
	if got := <-messages; !strings.Contains(got, "HMC admission limit reached: 1 connections rejected") {
		t.Fatal(got)
	}
	for range 99 {
		w.reject(now.Add(time.Second))
	}
	select {
	case got := <-messages:
		t.Fatalf("per-connection log: %s", got)
	default:
	}
	w.reject(now.Add(time.Minute))
	if got := <-messages; !strings.Contains(got, "HMC admission limit reached: 100 connections rejected") {
		t.Fatal(got)
	}
}

func TestAdmissionFloodResponsiveNoGoroutineLeak(t *testing.T) {
	runAdmissionFlood(t, false)
}

func TestAdmissionCreditedSameIPFlood(t *testing.T) {
	runAdmissionFlood(t, true)
}

func runAdmissionFlood(t *testing.T, sameIPCredit bool) {
	PrepareSecret(testPassword)
	_ = testPublicKey(t)
	baseline := runtime.NumGoroutine()
	c := admissionConfig(t)
	c.MaxPreAuth, c.MaxPreAuthPerIp, c.RatePerIp, c.BurstPerIp = 8, 4, 1, 8
	defer admissionPolicies.Delete(c.admissionPolicy())
	var warm *knockAttempt
	if sameIPCredit {
		warm = admissionAttempt(t, c.admission(), netip.MustParseAddr("127.0.0.2"), newReplayCache(16, time.Minute), time.Now(), "")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var rejected atomic.Int64
	var handlers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			wrapped, err := c.WrapConnServer(raw)
			if err != nil {
				t.Errorf("wrapping must not fail under flood: %v", err)
				continue
			}
			handlers.Go(func() {
				defer wrapped.Close()
				var payload [1]byte
				n, err := io.ReadFull(wrapped, payload[:])
				if errors.Is(err, errAdmissionRejected) {
					rejected.Add(1)
					return
				}
				if err == nil && n == 1 {
					_, _ = wrapped.Write(payload[:])
				}
			})
		}
	}()
	release := make(chan struct{})
	var flood sync.WaitGroup
	var dialErrors atomic.Int64
	for range 2000 {
		flood.Go(func() {
			d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: 10 * time.Second}
			raw, err := d.Dial("tcp4", listener.Addr().String())
			if err != nil {
				dialErrors.Add(1)
				return
			}
			defer raw.Close()
			<-release
		})
	}
	var releaseOnce sync.Once
	defer func() {
		releaseOnce.Do(func() { close(release) })
		flood.Wait()
		listener.Close()
		<-acceptDone
		handlers.Wait()
	}()
	eventually(t, func() bool { return rejected.Load() >= 100 && admissionCount(c.admission()) == 4 })
	source := "127.0.0.3"
	if sameIPCredit {
		eventually(t, func() bool { return rejected.Load() >= 1997 })
		if !warm.finish(t) {
			t.Fatal("pre-admitted valid proof could not earn credit during same-IP flood")
		}
		source = "127.0.0.2"
	}
	started := time.Now()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}, Timeout: 5 * time.Second}
	raw, err := d.Dial("tcp4", listener.Addr().String())
	if err == nil {
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		var client *clientConn
		client, err = newClientConn(raw, []loginProfile{testLoginProfile("stress_user")}, c.Password, "localhost")
		if err == nil {
			_, err = client.Write([]byte{42})
			if err == nil {
				var got [1]byte
				_, err = io.ReadFull(client, got[:])
				if err == nil && got[0] != 42 {
					err = fmt.Errorf("payload mismatch")
				}
			}
			client.Close()
		}
		raw.Close()
	}
	echoElapsed := time.Since(started)
	eventually(t, func() bool { return rejected.Load() >= 1996 })
	releaseOnce.Do(func() { close(release) })
	flood.Wait()
	listener.Close()
	<-acceptDone
	handlers.Wait()
	if err != nil {
		t.Fatalf("legitimate client starved by flood: %v", err)
	}
	if echoElapsed > 5*time.Second {
		t.Fatalf("unresponsive: %s", echoElapsed)
	}
	if dialErrors.Load() != 0 || rejected.Load() < 1996 {
		t.Fatalf("dial errors=%d rejected=%d", dialErrors.Load(), rejected.Load())
	}
	if admissionCount(c.admission()) != 0 {
		t.Fatal("flood leaked slots")
	}
	eventually(t, func() bool { return runtime.NumGoroutine() <= baseline+1 })
	t.Logf("2000 flood dials: %d rejected; knocked echo source=%s same-IP credit=%t completed in %s; goroutines baseline=%d final=%d", rejected.Load(), source, sameIPCredit, echoElapsed, baseline, runtime.NumGoroutine())
}

func BenchmarkAdmissionAccept(b *testing.B) {
	a := testAdmission(b, 2048, 64, 1000000, 1000000)
	ip := netip.MustParseAddr("127.0.0.1")
	now := fallbackTime
	a.now = func() time.Time { now = now.Add(time.Millisecond); return now }
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		l := a.acquire(ip)
		if l == nil {
			b.Fatal("unexpected rate rejection")
		}
		l.release()
	}
}
