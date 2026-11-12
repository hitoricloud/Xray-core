package hmc

import (
	"net/netip"
	"testing"
	"time"
)

func insiderIP(n, h int) netip.Addr { return netip.AddrFrom4([4]byte{198, 51, byte(n), byte(h)}) }

func TestAdmissionInsiderPostKnockCannotFillGlobal(t *testing.T) {
	now := fallbackTime
	a := newAdmissionLimiter((&Config{TrustedSources: []string{"192.0.2.250"}}).admissionPolicy(), admissionSources, func() time.Time { return now })
	newcomer := netip.MustParseAddr("203.0.113.5")
	seedAdmissionCredit(t, a, newcomer)
	var held []*admissionLease
	defer func() {
		for _, l := range held {
			l.release()
		}
	}()
	for n := 0; n < 4; n++ {
		for h := 1; h <= 2; h++ {
			s := insiderIP(n, h)
			seedAdmissionCredit(t, a, s)
			for range 256 {
				l := a.acquire(s, &admissionStubConn{})
				if l == nil {
					continue
				}
				if !l.postKnock() {
					l.release()
					continue
				}
				held = append(held, l)
			}
		}
	}
	t.Logf("8 credited IPs, 4 /24s, 2048 attempted pending slots: held=%d", a.pre)
	now = now.Add(6 * time.Second)
	for _, s := range []netip.Addr{netip.MustParseAddr("192.0.2.9"), newcomer, netip.MustParseAddr("192.0.2.250")} {
		l := a.acquire(s, &admissionStubConn{})
		if l == nil {
			t.Errorf("newcomer %s starved by proofless insiders", s)
		} else {
			held = append(held, l)
		}
	}
	if len(held) != 259 {
		t.Errorf("8 credited sources must hold exactly 256 pending slots plus 3 newcomers: %d", len(held))
	}
}

func TestAdmissionInsiderMixedCannotFillGlobal(t *testing.T) {
	now := fallbackTime
	a := newAdmissionLimiter((&Config{}).admissionPolicy(), admissionSources, func() time.Time { return now })
	newcomer := netip.MustParseAddr("203.0.113.5")
	seedAdmissionCredit(t, a, newcomer)
	creds := []netip.Addr{insiderIP(100, 1), insiderIP(100, 2)}
	for _, s := range creds {
		seedAdmissionCredit(t, a, s)
	}
	var held []*admissionLease
	defer func() {
		for _, l := range held {
			l.release()
		}
	}()
	for n := 0; n < 3; n++ {
		for h := 1; h <= 8; h++ {
			s := netip.AddrFrom4([4]byte{10, 0, byte(n), byte(h)})
			for i := 0; i < 64; i++ {
				if i == 60 {
					now = now.Add(time.Second)
				}
				l := a.acquire(s, &admissionStubConn{})
				if l == nil {
					continue
				}
				if !l.postKnock() {
					l.release()
					continue
				}
				held = append(held, l)
			}
		}
	}
	for _, s := range creds {
		for range 256 {
			l := a.acquire(s, &admissionStubConn{})
			if l == nil {
				continue
			}
			if !l.postKnock() {
				l.release()
				continue
			}
			held = append(held, l)
		}
	}
	t.Logf("24 uncredited + 2 credited sources: pending=%d uncredited=%d", a.pre, a.uncredited)
	now = now.Add(6 * time.Second)
	for _, s := range []netip.Addr{netip.MustParseAddr("192.0.2.9"), newcomer} {
		l := a.acquire(s, &admissionStubConn{})
		if l == nil {
			t.Errorf("newcomer %s starved by mixed insiders", s)
		} else {
			held = append(held, l)
		}
	}
	if len(held) != 258 {
		t.Errorf("mixed sources must hold exactly 192+64 pending slots plus 2 newcomers: %d", len(held))
	}
}
