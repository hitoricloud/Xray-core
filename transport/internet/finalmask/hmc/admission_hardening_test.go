package hmc

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	"google.golang.org/protobuf/proto"
)

type admissionStubConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *admissionStubConn) Close() error                   { c.closed.Store(true); return nil }
func (*admissionStubConn) SetReadDeadline(time.Time) error  { return nil }
func (*admissionStubConn) SetWriteDeadline(time.Time) error { return nil }

func seedAdmissionCredit(t testing.TB, a *admissionLimiter, source netip.Addr) {
	t.Helper()
	l := a.acquire(source)
	if l == nil {
		t.Fatal("credit bootstrap rejected")
	}
	l.credit()
	l.release()
}

func TestAdmissionTwoCreditedSourcesCannotFillGlobalCap(t *testing.T) {
	testCreditedMonopoly(t, []string{"198.51.100.1", "203.0.113.1"}, 512)
}

func TestAdmissionIPv6CreditedSlash64sCannotFillGlobalCap(t *testing.T) {
	testCreditedMonopoly(t, []string{"2001:db8:1:1::1", "2001:db8:1:2::1"}, 512)
}

func testCreditedMonopoly(t *testing.T, sources []string, want int) {
	now := fallbackTime
	a := testAdmission(t, 2048, 64, 1000000, 1000000)
	a.now = func() time.Time { return now }
	third := netip.MustParseAddr("192.0.2.77")
	seedAdmissionCredit(t, a, third)
	var held []*admissionLease
	defer func() {
		for _, l := range held {
			l.release()
		}
	}()
	for _, text := range sources {
		source := netip.MustParseAddr(text)
		seedAdmissionCredit(t, a, source)
		before := len(held)
		for i := 0; i < 2049; i++ {
			l := a.acquire(source, &admissionStubConn{})
			if l == nil {
				break
			}
			held = append(held, l)
		}
		if len(held)-before != 256 {
			t.Fatalf("credited source held %d slots; want 256", len(held)-before)
		}
	}
	if len(held) != want {
		t.Fatalf("two credited sources held %d slots; want %d", len(held), want)
	}
	now = now.Add(3 * time.Second)
	for _, source := range []netip.Addr{netip.MustParseAddr("192.0.2.9"), third} {
		l := a.acquire(source, &admissionStubConn{})
		if l == nil {
			t.Fatal("new source starved by credited holders")
		}
		held = append(held, l)
	}
}

func TestAdmissionEvictsWhenGlobalFullButUncreditedBelowQuota(t *testing.T) {
	now := fallbackTime
	a := testAdmission(t, 8, 2, 100, 100)
	a.now = func() time.Time { return now }
	var held []*admissionLease
	defer func() {
		for _, l := range held {
			l.release()
		}
	}()
	for i := 0; i < 3; i++ {
		source := netip.AddrFrom4([4]byte{198, 51, byte(i), 1})
		seedAdmissionCredit(t, a, source)
		for range 2 {
			held = append(held, a.acquire(source, &admissionStubConn{}))
		}
	}
	held = append(held, a.acquire(netip.MustParseAddr("10.0.0.1"), &admissionStubConn{}))
	trusted := netip.MustParseAddr("192.0.2.250")
	a.trusted = []netip.Prefix{netip.PrefixFrom(trusted, 32)}
	held = append(held, a.acquire(trusted, &admissionStubConn{}))
	for _, l := range held {
		if l == nil {
			t.Fatal("fixture rejected")
		}
	}
	source := netip.MustParseAddr("203.0.113.7")
	a.mu.Lock()
	e := a.creditLRU.PushFront(&admissionBucket{source: source, at: now})
	a.credits[source] = e
	a.mu.Unlock()
	now = now.Add(3 * time.Second)
	l := a.acquire(source, &admissionStubConn{})
	if l == nil {
		t.Fatalf("global-full credited attempt could not evict; uncredited=%d", a.uncredited)
	}
	held = append(held, l)
	if !held[6].evicted || held[0].evicted {
		t.Fatal("did not prefer oldest uncredited slot")
	}
	l = a.acquire(netip.MustParseAddr("192.0.2.1"), &admissionStubConn{})
	if l == nil {
		t.Fatal("global-full fresh source could not evict")
	}
	held = append(held, l)
	if !held[0].evicted || held[7].evicted {
		t.Fatal("oldest credited pre-knock not evicted or trusted pre-knock evicted")
	}
	l = a.acquire(netip.MustParseAddr("192.0.3.1"), &admissionStubConn{})
	if l == nil || !held[1].evicted {
		t.Fatal("second oldest credited pre-knock slot not evicted after uncredited queue exhausted")
	}
	held = append(held, l)
	for _, l := range held {
		l.release()
		l.release()
	}
	if a.pre != 0 || a.uncredited != 0 || len(a.preIP) != 0 {
		t.Fatal("eviction release leaked")
	}
}

func TestAdmissionSmallLimitsAndTrustedValidation(t *testing.T) {
	for pre := uint32(1); pre < 8; pre++ {
		c := &Config{Password: testPassword, MaxPreAuth: pre}
		if c.ValidateAdmission() == nil {
			t.Fatalf("small maxPreAuth=%d accepted", pre)
		}
		if _, err := c.WrapConnServer(nil); err == nil {
			t.Fatal("protobuf bypassed small-limit validation")
		}
	}
	for _, source := range []string{"0.0.0.0/0", "::/0", "1.2.3.4/7", "2001:db8::/31", "::ffff:1.2.3.4/103", "::ffff:1.2.3.4/95"} {
		c := &Config{Password: testPassword, TrustedSources: []string{source}}
		if c.ValidateAdmission() == nil {
			t.Fatalf("broad prefix accepted: %s", source)
		}
		if _, err := c.WrapConnServer(nil); err == nil {
			t.Fatal("protobuf bypassed trusted validation")
		}
	}
	for _, source := range []string{"0.0.0.0/8", "::/32", "1.2.3.4/8", "2001:db8::/32", "::ffff:1.2.3.4/104"} {
		if err := (&Config{TrustedSources: []string{source}}).ValidateAdmission(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAdmissionCanonicalTrustedPolicyAndClone(t *testing.T) {
	a := &Config{Password: testPassword, TrustedSources: []string{"unix", "1.2.3.4", "2001:db8::123/48", "1.2.3.4/32"}}
	b := proto.Clone(a).(*Config)
	b.TrustedSources = []string{"2001:db8::/48", "::ffff:1.2.3.4/128", "unix"}
	if a.admissionPolicy() != b.admissionPolicy() {
		t.Fatal("equivalent trusted sources split policy")
	}
	b.TrustedSources = []string{"1.2.3.5"}
	if a.admissionPolicy() == b.admissionPolicy() {
		t.Fatal("clone retained stale policy")
	}
}

func TestAdmissionCreditedAggregateCap(t *testing.T) {
	for _, sources := range [][]string{{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, {"2001:db8:1:1::1", "2001:db8:1:2::1", "2001:db8:1:3::1"}} {
		a := testAdmission(t, 2048, 400, 1000000, 1000000)
		for _, s := range sources {
			seedAdmissionCredit(t, a, netip.MustParseAddr(s))
		}
		var held []*admissionLease
		for i, n := range []int{400, 112} {
			for range n {
				l := a.acquire(netip.MustParseAddr(sources[i]), &admissionStubConn{})
				if l == nil {
					t.Fatal("credited cap rejected early")
				}
				held = append(held, l)
			}
		}
		if a.acquire(netip.MustParseAddr(sources[1])) != nil || a.acquire(netip.MustParseAddr(sources[2])) != nil {
			t.Fatal("credited aggregate exceeded reserve")
		}
		held[0].release()
		l := a.acquire(netip.MustParseAddr(sources[2]))
		if l == nil {
			t.Fatal("released credited aggregate slot unavailable")
		}
		l.release()
		for _, l := range held {
			l.release()
			l.release()
		}
		if len(a.creditedAggregates) != 0 || a.creditedOldest != nil || a.creditedNewest != nil || a.pre != 0 {
			t.Fatal("credited aggregate release leaked")
		}
	}
}

func TestAdmissionCachedServerPolicyConcurrentClone(t *testing.T) {
	c := &Config{Password: testPassword, CamouflagePublicKey: []byte{1}, TrustedSources: []string{"1.2.3.4"}}
	defer admissionPolicies.Delete(c.admissionPolicy())
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			wrapped, err := c.WrapConnServer(&admissionStubConn{})
			if err != nil {
				t.Error(err)
				return
			}
			defer wrapped.Close()
			if wrapped.(*serverConn).limiter != c.admission() {
				t.Error("cached policy not shared")
			}
		})
	}
	wg.Wait()
	clone := proto.Clone(c).(*Config)
	wrapped, err := clone.WrapConnServer(&admissionStubConn{})
	if err != nil {
		t.Fatal(err)
	}
	wrapped.Close()
	a, _ := serverAdmissions.Load(weak.Make(c))
	b, _ := serverAdmissions.Load(weak.Make(clone))
	if a == b {
		t.Fatal("proto clone reused pointer-cache entry")
	}
	bad := proto.Clone(c).(*Config)
	bad.TrustedSources = []string{"::/0"}
	if _, err := bad.WrapConnServer(nil); err == nil {
		t.Fatal("clone bypassed cached validation")
	}
}

func TestAdmissionCreditOnRetiredLeaseLost(t *testing.T) {
	var r admissionRegistry
	p := (&Config{}).admissionPolicy()
	now := fallbackTime
	a := r.lookup(p, now)
	a.now = func() time.Time { return now }
	source := netip.MustParseAddr("192.0.2.1")
	l := a.acquire(source)
	now = now.Add(admissionIdle)
	r.sweep(now)
	l.credit()
	l.release()
	if len(a.credits) != 0 {
		t.Fatal("credit repopulated retired limiter")
	}
	b := r.lookup(p, now)
	defer r.Delete(p)
	if b == a || b.credited(source, now) {
		t.Fatal("retired lease transferred credit")
	}
}

func BenchmarkWrapConnServerTrusted256(b *testing.B) {
	c := &Config{Password: testPassword, CamouflagePublicKey: []byte{1}}
	for i := 0; i < 256; i++ {
		c.TrustedSources = append(c.TrustedSources, fmt.Sprintf("2001:db8:%x::/48", i))
	}
	defer admissionPolicies.Delete(c.admissionPolicy())
	conn := &admissionStubConn{}
	warm, err := c.WrapConnServer(conn)
	if err != nil {
		b.Fatal(err)
	}
	warm.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		wrapped, err := c.WrapConnServer(conn)
		if err != nil {
			b.Fatal(err)
		}
		wrapped.Close()
	}
}
