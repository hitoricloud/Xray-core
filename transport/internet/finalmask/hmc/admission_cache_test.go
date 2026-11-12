package hmc

import (
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"
	"weak"

	"google.golang.org/protobuf/proto"
)

func serverAdmissionEntries() (n int) {
	serverAdmissions.Range(func(any, any) bool { n++; return true })
	return
}

func TestAdmissionConfigCacheCleanupAndLiveClone(t *testing.T) {
	base := &Config{Password: testPassword}
	defer admissionPolicies.Delete(base.admissionPolicy())
	live, err := base.serverAdmission()
	if err != nil {
		t.Fatal(err)
	}
	before := serverAdmissionEntries()
	populate := func() {
		for range 1000 {
			c := proto.Clone(base).(*Config)
			a, err := c.serverAdmission()
			if err != nil || a != live {
				t.Fatal("cloned config did not share live policy", err)
			}
		}
	}
	populate()
	deadline := time.Now().Add(5 * time.Second)
	for serverAdmissionEntries() > before+2 && time.Now().Before(deadline) {
		runtime.GC()
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	after := serverAdmissionEntries()
	if after > before+2 {
		t.Fatalf("1000 dropped configs retained cache: before=%d after=%d", before, after)
	}
	if entry, ok := serverAdmissions.Load(weak.Make(base)); !ok || entry.(*cachedServerAdmission).limiter != live {
		t.Fatal("live config entry lost")
	}
	again, err := base.serverAdmission()
	if err != nil || again != live {
		t.Fatal("live config behavior changed", err)
	}
	runtime.KeepAlive(base)
	t.Logf("1000 dropped cloned configs: cache entries before=%d after GC=%d", before, after)
}

func TestAdmissionCachedRetiredLimiterReplaced(t *testing.T) {
	c := &Config{Password: testPassword, TrustedSources: []string{"192.0.2.221"}}
	defer admissionPolicies.Delete(c.admissionPolicy())
	first, err := c.serverAdmission()
	if err != nil {
		t.Fatal(err)
	}
	admissionPolicies.sweep(time.Now().Add(admissionIdle + time.Second))
	second, err := c.serverAdmission()
	if err != nil || second == first {
		t.Fatal("cached retired limiter not replaced", err)
	}
	entry, _ := serverAdmissions.Load(weak.Make(c))
	if entry.(*cachedServerAdmission).limiter != second {
		t.Fatal("replacement not stored in config cache")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 3 {
				current, err := c.serverAdmission()
				if err != nil || current != second {
					t.Error("live cached limiter changed", err)
					return
				}
				lease := current.acquire(netip.MustParseAddr("192.0.2.221"))
				if lease == nil || lease.limiter != second {
					t.Error("acquire used retired registry path")
					return
				}
				lease.release()
			}
		})
	}
	wg.Wait()
	runtime.KeepAlive(c)
}

func TestAdmissionCreditedChurnStillBlocksNontrusted(t *testing.T) {
	now := fallbackTime
	trusted := netip.MustParseAddr("192.0.2.250")
	a := newAdmissionLimiter((&Config{TrustedSources: []string{trusted.String()}}).admissionPolicy(), admissionSources, func() time.Time { return now })
	newcomer := netip.MustParseAddr("203.0.113.5")
	seedAdmissionCredit(t, a, newcomer)
	var sources []netip.Addr
	for n := 0; n < 4; n++ {
		for h := 1; h <= 2; h++ {
			s := insiderIP(n, h)
			seedAdmissionCredit(t, a, s)
			sources = append(sources, s)
		}
	}
	var held []*admissionLease
	defer func() {
		for _, l := range held {
			l.release()
		}
	}()
	for _, s := range sources {
		for range 256 {
			l := a.acquire(s, &admissionStubConn{})
			if l == nil {
				break
			}
			held = append(held, l)
		}
	}
	if a.pre != 1844 {
		t.Fatalf("credited churn held %d, want 1844", a.pre)
	}
	now = now.Add(1900 * time.Millisecond)
	for _, s := range []netip.Addr{netip.MustParseAddr("192.0.2.1"), newcomer} {
		if l := a.acquire(s, &admissionStubConn{}); l != nil {
			l.release()
			t.Fatal("young credited churn unexpectedly evictable")
		}
	}
	l := a.acquire(trusted, &admissionStubConn{})
	if l == nil {
		t.Fatal("trusted gateway starved by credited churn")
	}
	held = append(held, l)
	now = now.Add(200 * time.Millisecond)
	for _, s := range []netip.Addr{netip.MustParseAddr("192.0.2.1"), newcomer} {
		l := a.acquire(s, &admissionStubConn{})
		if l == nil {
			t.Fatal("old credited pre-knock churn not evicted")
		}
		held = append(held, l)
	}
	t.Log("8 credited IPs across 4 /24s hold 1844 young pre-knock slots; nontrusted blocked at 1.9s, trusted admitted; nontrusted admitted at 2.1s")
}
