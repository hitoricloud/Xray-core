package hmc

import (
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"
)

func admissionAttempt(t *testing.T, a *admissionLimiter, source netip.Addr, cache *replayCache, now time.Time, knock String, dest ...string) *knockAttempt {
	t.Helper()
	raw, peer := tcpPair(t)
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	server, err := wrapConnServer(&admissionConn{Conn: peer, remote: &net.TCPAddr{IP: net.ParseIP(source.String())}}, nil, testPassword, testPublicKey(t))
	if err != nil {
		t.Fatal(err)
	}
	server.limiter, server.knocks, server.now = a, cache, func() time.Time { return now }
	if len(dest) != 0 {
		server.dest = dest[0]
	}
	done := make(chan error, 1)
	go func() { err := server.handshake(); server.Close(); done <- err }()
	t.Cleanup(func() { raw.Close(); server.Close() })
	uuid := testLoginProfile("test_user").UUID
	if knock == "" {
		knock = loginKnock(testPassword, "localhost", "test_user", uuid, now.Unix()/30)
	}
	if err := writeFull(raw, loginStartWire(t, knock, 2, uuid)); err != nil {
		t.Fatal(err)
	}
	request, err := readPacket(raw)
	if err != nil || request.packetID != 1 {
		t.Fatalf("Encryption Request: %v", err)
	}
	var id String
	var key, token Bytes
	if err := request.readFields(&id, &key, &token); err != nil {
		t.Fatal(err)
	}
	binding := loginBinding(775, knock, 25565, "test_user", uuid, id, key, token)
	secret, proof, keys, err := newLoginResponse(testPassword, binding, token, key)
	if err != nil {
		t.Fatal(err)
	}
	return &knockAttempt{server: server, raw: raw, done: done, secret: secret, proof: proof, keys: keys, token: token}
}

func TestAdmissionCreditOnlyAfterConsumedKnock(t *testing.T) {
	a := testAdmission(t, 8, 4, 100, 100)
	cache := newReplayCache(16, time.Minute)
	source, other := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")
	knock := loginKnock(testPassword, "localhost", "test_user", testLoginProfile("test_user").UUID, fallbackTime.Unix()/30)
	bad := admissionAttempt(t, a, source, cache, fallbackTime, knock)
	if a.credited(source, fallbackTime) {
		t.Fatal("MAC alone earned credit")
	}
	bad.proof[len(bad.proof)-1] ^= 1
	if err := writePacket(bad.raw, 1, &bad.secret, &bad.proof); err != nil {
		t.Fatal(err)
	}
	if err := <-bad.done; err == nil {
		t.Fatal("garbage proof accepted")
	}
	if a.credited(source, fallbackTime) || cache.contains(knockToken(knock), fallbackTime) {
		t.Fatal("garbage proof credited or consumed knock")
	}
	first := admissionAttempt(t, a, source, cache, fallbackTime, knock)
	replay := admissionAttempt(t, a, other, cache, fallbackTime, knock)
	if !first.finish(t) || !a.credited(source, fallbackTime) {
		t.Fatal("valid consumed knock not credited")
	}
	if replay.finish(t) || a.credited(other, fallbackTime) {
		t.Fatal("failed knock consumption credited replay source")
	}
}

func TestAdmissionCreditRateReserveAndConcurrentCap(t *testing.T) {
	a := testAdmission(t, 8, 2, 1, 1)
	credited := netip.MustParseAddr("127.0.0.1")
	seed := a.acquire(credited)
	seed.credit()
	seed.release()
	var leases []*admissionLease
	defer func() {
		for _, l := range leases {
			l.release()
		}
	}()
	for i := 0; i < 6; i++ {
		l := a.acquire(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}))
		if l == nil {
			t.Fatal("uncredited quota rejected early")
		}
		leases = append(leases, l)
	}
	if a.acquire(netip.MustParseAddr("10.0.1.1")) != nil {
		t.Fatal("uncredited source used reserve")
	}
	l := a.acquire(credited)
	if l == nil {
		t.Fatal("credited source denied shared reserve")
	}
	leases = append(leases, l)
	if a.acquire(credited) != nil {
		t.Fatal("credited source consumed trusted reserve")
	}
	trusted := netip.MustParseAddr("192.0.2.250")
	a.trusted = []netip.Prefix{netip.PrefixFrom(trusted, 32)}
	l = a.acquire(trusted)
	if l == nil {
		t.Fatal("trusted source denied separate reserve")
	}
	leases = append(leases, l)
	if a.acquire(trusted) != nil {
		t.Fatal("trusted source bypassed global cap")
	}
	for _, l := range leases {
		l.release()
	}
	if a.pre != 0 || a.uncredited != 0 || len(a.aggregates) != 0 {
		t.Fatal("reserve release leaked")
	}
	a = testAdmission(t, 2048, 1, 1, 1)
	seed = a.acquire(credited)
	seed.credit()
	seed.release()
	leases = nil
	for range 256 {
		l := a.acquire(credited)
		if l == nil {
			t.Fatal("credited source denied higher concurrency")
		}
		leases = append(leases, l)
	}
	if a.acquire(credited) != nil {
		t.Fatal("credited source cap bypassed")
	}
}

func TestAdmissionTrustedSourcesMatchingAndPolicy(t *testing.T) {
	cases := []struct {
		trusted, source string
		want            bool
	}{
		{"192.0.2.0/24", "192.0.2.27", true}, {"192.0.2.1", "::ffff:192.0.2.1", true},
		{"::ffff:192.0.2.0/120", "192.0.2.3", true}, {"::ffff:192.0.2.1", "192.0.2.1", true},
		{"2001:db8::5", "2001:db8::5", true}, {"2001:db8::5", "2001:db8::6", false},
		{"2001:db8:1::/48", "2001:db8:1:ffff::1", true}, {"2001:db8:1::/48", "2001:db8:2::1", false},
		{"unix", "", true}, {"127.0.0.1", "", false}, {"unix", "127.0.0.1", false},
	}
	for _, tc := range cases {
		t.Run(tc.trusted+"/"+tc.source, func(t *testing.T) {
			c := &Config{TrustedSources: []string{tc.trusted}, MaxPreAuth: 8, MaxPreAuthPerIp: 1, RatePerIp: 1, BurstPerIp: 1}
			if err := c.ValidateAdmission(); err != nil {
				t.Fatal(err)
			}
			a := newAdmissionLimiter(c.admissionPolicy(), 16, func() time.Time { return fallbackTime })
			var source netip.Addr
			if tc.source != "" {
				source = netip.MustParseAddr(tc.source)
			}
			first := a.acquire(source)
			if first == nil {
				t.Fatal("first acquire")
			}
			defer first.release()
			for range 7 {
				l := a.acquire(source)
				if (l != nil) != tc.want {
					t.Fatalf("trusted match=%t want=%t", l != nil, tc.want)
				}
				defer l.release()
			}
			if tc.want && a.acquire(source) != nil {
				t.Fatal("trusted source bypassed global cap")
			}
		})
	}
	c := &Config{Password: testPassword, TrustedSources: []string{"127.0.0.1"}}
	other := &Config{Password: testPassword, TrustedSources: []string{"127.0.0.2"}}
	defer admissionPolicies.Delete(c.admissionPolicy())
	defer admissionPolicies.Delete(other.admissionPolicy())
	if c.admission() == other.admission() {
		t.Fatal("trusted lists shared policy")
	}
	c.TrustedSources = append(c.TrustedSources, "unix")
	defer admissionPolicies.Delete(c.admissionPolicy())
	if c.admission() == other.admission() {
		t.Fatal("unix policy not isolated")
	}
}

func TestAdmissionTrustedReserveAndMinimumSlots(t *testing.T) {
	trusted := netip.MustParseAddr("127.0.0.1")
	for _, cap := range []uint32{8, 16} {
		c := &Config{MaxPreAuth: cap, TrustedSources: []string{trusted.String()}}
		a := newAdmissionLimiter(c.admissionPolicy(), 16, func() time.Time { return fallbackTime })
		var leases []*admissionLease
		for i := uint32(0); i < cap-cap/4; i++ {
			l := a.acquire(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}))
			if l == nil {
				t.Fatal("ordinary quota rejected early")
			}
			leases = append(leases, l)
		}
		if a.acquire(netip.MustParseAddr("10.0.1.1")) != nil {
			t.Fatal("uncredited source used reserved slot")
		}
		for range cap / 4 {
			l := a.acquire(trusted)
			if l == nil {
				t.Fatal("trusted source denied reserve")
			}
			leases = append(leases, l)
		}
		if a.acquire(trusted) != nil {
			t.Fatal("trusted source exceeded global cap")
		}
		for _, l := range leases {
			l.release()
		}
	}
}

func TestAdmissionAggregateCapsAndExemptions(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		a := testAdmission(t, 4096, 64, 1000000, 1000000)
		var leases []*admissionLease
		limit := 512
		if ipv6 {
			limit = 256
		}
		for i := 0; i < limit; i++ {
			source := netip.AddrFrom4([4]byte{10, 1, 2, byte(i / 4)})
			if ipv6 {
				source = netip.AddrFrom16([16]byte{0x20, 1, 0xd, 0xb8, 0, 1, byte(i >> 8), byte(i)})
			}
			l := a.acquire(source)
			if l == nil {
				t.Fatalf("aggregate rejected %d/%d", i, limit)
			}
			leases = append(leases, l)
		}
		source := netip.MustParseAddr("10.1.2.254")
		outside := netip.MustParseAddr("10.1.3.1")
		if ipv6 {
			source = netip.MustParseAddr("2001:db8:1:ffff::1")
			outside = netip.MustParseAddr("2001:db8:2::1")
		}
		if a.acquire(source) != nil {
			t.Fatal("aggregate cap bypassed")
		}
		l := a.acquire(outside)
		if l == nil {
			t.Fatal("independent aggregate rejected")
		}
		l.release()
		leases[0].credit()
		l = a.acquire(leases[0].source)
		if l == nil {
			t.Fatal("credit did not exempt aggregate")
		}
		l.release()
		a.trusted = []netip.Prefix{netip.PrefixFrom(source, source.BitLen())}
		l = a.acquire(source)
		if l == nil {
			t.Fatal("trusted source did not exempt aggregate")
		}
		l.release()
		for _, l := range leases {
			l.release()
			l.release()
		}
		if a.pre != 0 || len(a.aggregates) != 0 {
			t.Fatal("aggregate release leaked")
		}
	}
}

func TestAdmissionOldestEvictionAndProtectedConnections(t *testing.T) {
	a := testAdmission(t, 4, 4, 100, 100)
	now := fallbackTime
	a.now = func() time.Time { return now }
	var leases []*admissionLease
	var peers []net.Conn
	add := func(source string) *admissionLease {
		x, y := net.Pipe()
		t.Cleanup(func() { x.Close(); y.Close() })
		l := a.acquire(netip.MustParseAddr(source), x)
		if l == nil {
			t.Fatal("initial acquire")
		}
		leases = append(leases, l)
		peers = append(peers, y)
		return l
	}
	first := add("10.0.0.1")
	now = now.Add(time.Millisecond)
	protected := add("10.0.0.2")
	protected.postKnock()
	now = now.Add(time.Millisecond)
	third := add("10.0.0.3")
	source := netip.MustParseAddr("10.0.0.4")
	if a.acquire(source) != nil {
		t.Fatal("young connection evicted")
	}
	now = fallbackTime.Add(admissionEvictWait)
	if a.acquire(source) != nil {
		t.Fatal("eviction at exactly two seconds")
	}
	now = now.Add(time.Nanosecond)
	replacement := a.acquire(source)
	if replacement == nil || !first.evicted || protected.evicted || third.evicted {
		t.Fatal("did not evict only oldest pre-knock")
	}
	var b [1]byte
	if n, err := peers[0].Read(b[:]); n != 0 || err != io.EOF {
		t.Fatalf("evicted socket: %d %v", n, err)
	}
	first.release()
	first.release()
	dest, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()
	limits := fallbackLimits
	limits.idle, limits.total = time.Millisecond, time.Millisecond
	first.relay(peers[0], dest.Addr().String(), nil, limits)
	_ = dest.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Millisecond))
	if conn, err := dest.Accept(); err == nil {
		conn.Close()
		t.Fatal("evicted handshake entered fallback")
	}
	if a.pre != 3 {
		t.Fatal("evicted double release stole a slot")
	}
	replacement.release()
	third.credit()
	now = now.Add(3 * time.Second)
	fourth := add("10.0.0.5")
	replacement = a.acquire(netip.MustParseAddr("10.0.0.7"))
	if replacement == nil || !third.evicted {
		t.Fatal("credit incorrectly protected an older pre-knock slot")
	}
	defer replacement.release()
	if protected.evicted || fourth.evicted {
		t.Fatal("post-knock or young source evicted")
	}
	for _, l := range append(leases, fourth) {
		l.release()
	}
	replacement.release()
	if a.pre != 0 || a.uncredited != 0 || a.oldest != nil || a.newest != nil {
		t.Fatal("eviction leaked counters or queue")
	}
}

func TestAdmissionCreditTTLRefreshLRUAndBound(t *testing.T) {
	a := testAdmission(t, 8, 4, 100, 100)
	a.capacity = admissionSources
	now := fallbackTime
	a.now = func() time.Time { return now }
	credit := func(ip netip.Addr) {
		t.Helper()
		l := a.acquire(ip)
		if l == nil {
			t.Fatal("credit fixture admission")
		}
		l.credit()
		l.release()
	}
	first := netip.MustParseAddr("10.0.0.1")
	credit(first)
	now = now.Add(admissionIdle - time.Second)
	l := a.acquire(first)
	l.release()
	now = now.Add(time.Second)
	if a.credited(first, now) {
		t.Fatal("ordinary acquire refreshed credit TTL")
	}
	credit(first)
	now = now.Add(admissionIdle - time.Second)
	credit(first)
	now = now.Add(time.Second)
	if !a.credited(first, now) {
		t.Fatal("authenticated session did not refresh TTL")
	}
	for i := 0; i < 200000; i++ {
		if i%10000 == 0 {
			credit(first)
		}
		credit(netip.AddrFrom4([4]byte{11, byte(i >> 16), byte(i >> 8), byte(i)}))
		if len(a.credits) > admissionSources || a.creditLRU.Len() > admissionSources {
			t.Fatal("unbounded credit cache")
		}
	}
	if !a.credited(first, now) {
		t.Fatal("recently authenticated source evicted")
	}
	if a.credited(netip.MustParseAddr("11.0.0.0"), now) {
		t.Fatal("oldest credit retained under churn")
	}
	now = now.Add(admissionIdle)
	credit(netip.MustParseAddr("12.0.0.1"))
	if len(a.credits) != 1 {
		t.Fatal("expired credits not purged")
	}
}

func TestAdmissionRegistryExpiryJanitorLifecycle(t *testing.T) {
	baseline := runtime.NumGoroutine()
	ticks := make(chan time.Time)
	r := admissionRegistry{ticks: ticks}
	p := (&Config{}).admissionPolicy()
	now := time.Now()
	a := r.lookup(p, now)
	a.now = func() time.Time { return now }
	ip := netip.MustParseAddr("127.0.0.1")
	l := a.acquire(ip)
	l.credit()
	l.release()
	if len(a.buckets) == 0 || len(a.credits) == 0 {
		t.Fatal("fixture cache missing")
	}
	done := r.done
	now = now.Add(admissionIdle - time.Second)
	l = a.acquire(ip)
	l.release()
	r.sweep(now.Add(time.Second))
	if len(r.entries) != 1 {
		t.Fatal("active limiter expired")
	}
	now = now.Add(admissionIdle)
	ticks <- now
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("janitor did not stop")
	}
	if len(r.entries) != 0 || r.stop != nil || len(a.buckets) != 0 || len(a.credits) != 0 {
		t.Fatal("retired policy retained caches")
	}
	next := r.lookup(p, now)
	if next == a {
		t.Fatal("retired limiter reused")
	}
	next.now = func() time.Time { return now }
	l = a.acquire(ip)
	if l == nil || l.limiter != next {
		t.Fatal("old wrapper did not rebind to current policy")
	}
	l.credit()
	l.release()
	if len(a.buckets) != 0 || len(a.credits) != 0 {
		t.Fatal("old wrapper repopulated retired caches")
	}
	done = r.done
	newer := r.lookup(p, now.Add(admissionIdle))
	if newer == next {
		t.Fatal("lookup did not lazily expire")
	}
	r.Delete(p)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("restarted janitor leaked")
	}
	eventually(t, func() bool { return runtime.NumGoroutine() <= baseline })
}

func TestAdmissionCreditConcurrentReleaseStress(t *testing.T) {
	a := testAdmission(t, 32, 4, 1, 4)
	source := netip.MustParseAddr("127.0.0.1")
	seed := a.acquire(source)
	seed.credit()
	seed.release()
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 1000 {
				if l := a.acquire(source); l != nil {
					l.postKnock()
					l.credit()
					l.release()
					l.release()
				}
			}
		})
	}
	wg.Wait()
	if a.pre != 0 || a.uncredited != 0 || len(a.preIP) != 0 {
		t.Fatal("concurrent release leaked")
	}
}
