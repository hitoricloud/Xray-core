package hmc

import (
	"net/netip"
	"testing"
	"time"
)

func TestAdmissionProofVerifiedInsiderStillHoldsNontrustedBudget(t *testing.T) {
	now := fallbackTime
	trusted := netip.MustParseAddr("192.0.2.250")
	a := newAdmissionLimiter((&Config{TrustedSources: []string{trusted.String()}}).admissionPolicy(), admissionSources, func() time.Time { return now })
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
			if !l.postKnock() || !l.proofVerified() {
				t.Fatal("insider valid proof rejected")
			}
			held = append(held, l)
		}
	}
	if a.pre != 1844 || len(a.pendingIP) != 0 {
		t.Fatal("proof-verified budget changed")
	}
	now = now.Add(6 * time.Second)
	if l := a.acquire(netip.MustParseAddr("203.0.113.1"), &admissionStubConn{}); l != nil {
		l.release()
		t.Fatal("verified proof evicted")
	}
	l := a.acquire(trusted, &admissionStubConn{})
	if l == nil {
		t.Fatal("proof-verified insiders consumed trusted reserve")
	}
	held = append(held, l)
	t.Log("8 credited IPs in 4 /24s can hold 1844 proof-verified, acknowledgment-pending slots until the handshake deadline; trusted reserve remains available")
}

func TestAdmissionEvictionPrefersPreKnockThenPending(t *testing.T) {
	now := fallbackTime
	trusted := netip.MustParseAddr("192.0.2.250")
	a := newAdmissionLimiter((&Config{MaxPreAuth: 8, TrustedSources: []string{trusted.String()}}).admissionPolicy(), admissionSources, func() time.Time { return now })
	credited := netip.MustParseAddr("203.0.113.1")
	seedAdmissionCredit(t, a, credited)
	var held []*admissionLease
	defer func() {
		for _, l := range held {
			l.release()
		}
	}()
	add := func(s netip.Addr) *admissionLease {
		l := a.acquire(s, &admissionStubConn{})
		if l == nil {
			t.Fatal("fixture admission")
		}
		held = append(held, l)
		return l
	}
	pending := add(trusted)
	if !pending.postKnock() {
		t.Fatal("pending fixture")
	}
	now = now.Add(time.Millisecond)
	c := add(credited)
	now = now.Add(time.Millisecond)
	u := add(netip.MustParseAddr("192.0.2.1"))
	protected := add(trusted)
	if !protected.postKnock() || !protected.proofVerified() {
		t.Fatal("verified fixture")
	}
	for range 4 {
		add(trusted)
	}
	now = fallbackTime.Add(6 * time.Second)
	for i, victim := range []*admissionLease{u, c, pending} {
		add(trusted)
		if !victim.evicted || protected.evicted {
			t.Fatalf("eviction priority %d or proof protection violated", i)
		}
		if i == 0 && (c.evicted || pending.evicted) {
			t.Fatal("uncredited did not take priority")
		}
		if i == 1 && pending.evicted {
			t.Fatal("pending evicted before credited pre-knock")
		}
	}
}

func TestAdmissionPendingEvictionRespectsClassQuotas(t *testing.T) {
	now := fallbackTime
	trusted := netip.MustParseAddr("192.0.2.250")
	credited := netip.MustParseAddr("203.0.113.1")
	a := newAdmissionLimiter((&Config{MaxPreAuth: 8, TrustedSources: []string{trusted.String()}}).admissionPolicy(), admissionSources, func() time.Time { return now })
	seedAdmissionCredit(t, a, credited)
	var held []*admissionLease
	defer func() {
		for _, l := range held {
			l.release()
			l.release()
		}
	}()
	for _, source := range []netip.Addr{trusted, credited, insiderIP(0, 1), insiderIP(1, 1), insiderIP(2, 1), insiderIP(3, 1), insiderIP(4, 1), insiderIP(5, 1)} {
		l := a.acquire(source, &admissionStubConn{})
		if l == nil || !l.postKnock() {
			t.Fatal("pending quota fixture")
		}
		held = append(held, l)
	}
	now = now.Add(6 * time.Second)
	for i, source := range []netip.Addr{insiderIP(6, 1), credited, trusted} {
		l := a.acquire(source, &admissionStubConn{})
		if l == nil {
			t.Fatal("quota-compatible replacement rejected")
		}
		held = append(held, l)
		victim := []int{2, 1, 0}[i]
		if !held[victim].evicted {
			t.Fatal("replacement did not free the required class quota")
		}
		if a.pre != 8 || a.nontrusted > 7 || a.uncredited > 6 {
			t.Fatal("replacement exceeded class quota")
		}
	}
}

func TestAdmissionOverlappingTrustListsHaveSeparateBudgets(t *testing.T) {
	a := &Config{Password: testPassword, MaxPreAuth: 8, TrustedSources: []string{"192.0.2.0/24"}}
	b := &Config{Password: testPassword, MaxPreAuth: 8, TrustedSources: []string{"192.0.2.0/24", "192.0.2.1"}}
	defer admissionPolicies.Delete(a.admissionPolicy())
	defer admissionPolicies.Delete(b.admissionPolicy())
	if a.admission() == b.admission() {
		t.Fatal("overlapping unequal trust lists unexpectedly shared budgets")
	}
	for _, limiter := range []*admissionLimiter{a.admission(), b.admission()} {
		var leases []*admissionLease
		for range 8 {
			l := limiter.acquire(netip.MustParseAddr("192.0.2.1"))
			if l == nil {
				t.Fatal("separate policy budget rejected early")
			}
			leases = append(leases, l)
		}
		if limiter.acquire(netip.MustParseAddr("192.0.2.1")) != nil {
			t.Fatal("policy exceeded its own global cap")
		}
		for _, l := range leases {
			l.release()
		}
	}
}
