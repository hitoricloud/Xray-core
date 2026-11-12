package hmc

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdmissionPendingSourceCapsAndProofProtection(t *testing.T) {
	for _, kind := range []string{"uncredited", "credited", "trusted"} {
		t.Run(kind, func(t *testing.T) {
			now := fallbackTime
			a := testAdmission(t, 512, 64, 1000000, 1000000)
			a.now = func() time.Time { return now }
			source := netip.MustParseAddr("192.0.2.1")
			cap := pendingPerIP
			if kind == "credited" {
				seedAdmissionCredit(t, a, source)
				cap = pendingCreditedPerIP
			}
			if kind == "trusted" {
				a.trusted = []netip.Prefix{netip.PrefixFrom(source, 32)}
				cap = 512
			}
			var held []*admissionLease
			defer func() {
				for _, l := range held {
					l.release()
					l.release()
				}
			}()
			for range cap {
				l := a.acquire(source, &admissionStubConn{})
				if l == nil || !l.postKnock() {
					t.Fatal("pending cap rejected early")
				}
				held = append(held, l)
			}
			extra := a.acquire(source, &admissionStubConn{})
			if kind == "trusted" {
				if extra != nil {
					t.Fatal("trusted exceeded global cap")
				}
			} else {
				if extra == nil {
					t.Fatal("pre-knock incorrectly capped by pending cap")
				}
				if extra.postKnock() {
					t.Fatal("source exceeded post-knock cap")
				}
				extra.release()
			}
			if !held[0].proofVerified() {
				t.Fatal("valid proof rejected")
			}
			now = now.Add(6 * time.Second)
			if held[0].pending || held[0].queued || a.pendingIP[source] != cap-1 {
				t.Fatal("proof left evictable pending state")
			}
			replacement := a.acquire(source, &admissionStubConn{})
			if replacement == nil || !replacement.postKnock() {
				t.Fatal("verified proof did not free pending capacity")
			}
			held = append(held, replacement)
			if held[0].evicted {
				t.Fatal("verified proof evicted")
			}
			for _, l := range held {
				l.release()
				l.release()
			}
			if a.pre != 0 || a.nontrusted != 0 || len(a.pendingIP) != 0 || a.pendingOldest != nil || a.pendingNewest != nil {
				t.Fatal("pending release leaked")
			}
		})
	}
}

func TestAdmissionPendingEvictionReleasesTokenAndLease(t *testing.T) {
	now := fallbackTime
	trusted := netip.MustParseAddr("192.0.2.250")
	a := newAdmissionLimiter((&Config{TrustedSources: []string{trusted.String()}}).admissionPolicy(), admissionSources, func() time.Time { return now })
	credited := netip.MustParseAddr("203.0.113.5")
	seedAdmissionCredit(t, a, credited)
	var held []*admissionLease
	defer func() {
		for _, l := range held {
			l.release()
			l.release()
		}
	}()
	add := func(s netip.Addr) bool {
		l := a.acquire(s, &admissionStubConn{})
		if l == nil {
			return false
		}
		var token [18]byte
		copy(token[:], "pending-eviction")
		binary.BigEndian.PutUint32(token[14:], uint32(len(held)))
		slot := acquireKnockSlot(token[:])
		if slot == nil || !l.postKnock(slot) {
			l.release()
			slot.release()
			return false
		}
		held = append(held, l)
		return true
	}
	for n := 0; n < 58; n++ {
		s := insiderIP(n/2, n%2+1)
		seedAdmissionCredit(t, a, s)
		for range 32 {
			if !add(s) {
				break
			}
		}
	}
	if a.pre != 1844 {
		t.Fatalf("nontrusted held %d, want 1844", a.pre)
	}
	if add(credited) {
		t.Fatal("insider consumed trusted reserve")
	}
	for range 204 {
		if !add(trusted) {
			t.Fatal("trusted denied separate reserve")
		}
	}
	if a.pre != 2048 || add(trusted) {
		t.Fatal("trusted reserve/global cap wrong")
	}
	now = now.Add(5 * time.Second)
	if a.acquire(credited, &admissionStubConn{}) != nil {
		t.Fatal("pending evicted at exactly 5s")
	}
	now = fallbackTime.Add(6 * time.Second)
	for i, s := range []netip.Addr{netip.MustParseAddr("192.0.2.9"), credited, trusted} {
		l := a.acquire(s, &admissionStubConn{})
		if l == nil {
			t.Fatalf("+6s newcomer %s starved", s)
		}
		held = append(held, l)
		victim := held[i]
		if !victim.evicted || !victim.released || !victim.slotReleased() {
			t.Fatal("pending eviction leaked token/lease")
		}
		if victim.proofVerified() {
			t.Fatal("evicted-then-late proof accepted")
		}
		victim.release()
		victim.release()
		victim.slot.release()
		if a.pre != 2048 {
			t.Fatal("evicted double release stole a slot")
		}
		dest, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		victim.relay(&admissionStubConn{}, dest.Addr().String(), []byte("must not relay"), fallbackLimits)
		_ = dest.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Millisecond))
		if c, err := dest.Accept(); err == nil {
			c.Close()
			t.Error("evicted pending connection relayed")
		}
		dest.Close()
	}
	t.Log("58 credited IPs across 29 /24s held 1844 pending slots; 204 trusted reserve slots; at +6s all three newcomers evicted oldest pending slots")
	for _, l := range held {
		l.release()
		l.release()
	}
	if a.pre != 0 || a.nontrusted != 0 || len(a.pendingIP) != 0 || len(a.preIP) != 0 || a.pendingOldest != nil {
		t.Fatal("pending eviction bookkeeping leak")
	}
}

func (l *admissionLease) slotReleased() bool {
	activeKnocks.Lock()
	defer activeKnocks.Unlock()
	return activeKnocks.tokens[l.slot.token] == 0
}

func TestAdmissionEvictedLateProofSilent(t *testing.T) {
	a := testAdmission(t, 8, 8, 100, 100)
	var clock atomic.Int64
	clock.Store(fallbackTime.UnixNano())
	a.now = func() time.Time { return time.Unix(0, clock.Load()) }
	cache := newReplayCache(16, time.Minute)
	fake := newFakeDest(t, func(_ net.Conn, r io.Reader) { _, _ = io.Copy(io.Discard, r) })
	entry := newDestEntry()
	entry.next = entry.now().Add(time.Hour)
	destKeys.Store(destKey(fake.address(), 0), entry)
	attempt := admissionAttempt(t, a, netip.MustParseAddr("127.0.0.1"), cache, fallbackTime, "", fake.address())
	var held []*admissionLease
	defer func() {
		for _, l := range held {
			l.release()
		}
	}()
	for i := 0; i < 5; i++ {
		l := a.acquire(netip.AddrFrom4([4]byte{10, byte(i), 0, 1}), &admissionStubConn{})
		if l == nil || !l.postKnock() {
			t.Fatal("fixture admission failed")
		}
		held = append(held, l)
	}
	clock.Store(fallbackTime.Add(6 * time.Second).UnixNano())
	replacement := a.acquire(netip.MustParseAddr("192.0.2.1"), &admissionStubConn{})
	if replacement == nil {
		t.Fatal("pending victim not evicted")
	}
	defer replacement.release()
	_ = writePacket(attempt.raw, 1, &attempt.secret, &attempt.proof)
	if err := <-attempt.done; err == nil {
		t.Fatal("late proof accepted")
	}
	var b [1]byte
	if n, err := attempt.raw.Read(b[:]); n != 0 || err != io.EOF {
		t.Fatalf("late proof response: %d %v", n, err)
	}
	lease := attempt.server.admission
	if !lease.evicted || !lease.released || !lease.slotReleased() || lease.proofVerified() {
		t.Fatal("evicted pending lease/token/proof state wrong")
	}
	if cache.contains(lease.slot.token[:], fallbackTime) {
		t.Fatal("late proof consumed knock")
	}
	if len(fake.snapshots()) != 0 {
		t.Fatal("late proof triggered relay")
	}
}

func TestAdmissionNoCreditBeforeLoginAcknowledged(t *testing.T) {
	for _, ack := range []string{"missing", "invalid"} {
		t.Run(ack, func(t *testing.T) {
			a := testAdmission(t, 8, 4, 100, 100)
			source := netip.MustParseAddr("127.0.0.1")
			attempt := admissionAttempt(t, a, source, newReplayCache(16, time.Minute), fallbackTime, "")
			if err := writePacket(attempt.raw, 1, &attempt.secret, &attempt.proof); err != nil {
				t.Fatal(err)
			}
			reader, err := newCryptoReader(attempt.raw, attempt.keys.serverToClient)
			if err != nil {
				t.Fatal(err)
			}
			if pkt, err := readPacket(reader); err != nil || pkt.packetID != 2 {
				t.Fatal("Login Success", err)
			}
			a.mu.Lock()
			credited := a.credited(source, fallbackTime)
			pending := attempt.server.admission.pending
			a.mu.Unlock()
			if credited || pending {
				t.Fatal("valid proof earned early credit or remained evictable")
			}
			if ack == "invalid" {
				writer, err := newCryptoWriter(attempt.raw, attempt.keys.clientToServer)
				if err != nil {
					t.Fatal(err)
				}
				if err := writePacket(writer, 4); err != nil {
					t.Fatal(err)
				}
			} else {
				attempt.raw.Close()
			}
			if err := <-attempt.done; err == nil {
				t.Fatal("bad/missing acknowledgment accepted")
			}
			if a.credited(source, fallbackTime) {
				t.Fatal("failed Login Acknowledged earned credit")
			}
		})
	}
}
