package hmc

import (
	"container/list"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const (
	defaultMaxPreAuth      = 2048
	defaultMaxPreAuthPerIP = 64
	defaultMaxRelaysPerIP  = 16
	defaultRatePerIP       = 30
	defaultBurstPerIP      = 60
	admissionSources       = 65536
	admissionIdle          = 10 * time.Minute
	admissionEvictWait     = 2 * time.Second
	admissionProofWait     = 5 * time.Second
	pendingPerIP           = 8
	pendingCreditedPerIP   = 32
	MaxAdmissionLimit      = 1000000
	MaxTrustedSources      = 256
)

type admissionPolicy struct {
	pre, preIP, relayIP, rate, burst uint32
	password                         [32]byte
	trusted                          string
}

type admissionRegistry struct {
	mu      sync.Mutex
	entries map[admissionPolicy]*admissionLimiter
	stop    chan struct{}
	done    chan struct{}
	ticks   <-chan time.Time
}

var admissionPolicies admissionRegistry

func (c *Config) admissionPolicy() admissionPolicy {
	trusted, _ := c.normalizedTrustedSources()
	p := admissionPolicy{pre: c.MaxPreAuth, preIP: c.MaxPreAuthPerIp, relayIP: c.MaxRelaysPerIp, rate: c.RatePerIp, burst: c.BurstPerIp, password: sha256.Sum256([]byte(c.Password)), trusted: strings.Join(trusted, "\x00")}
	for _, v := range []struct {
		value    *uint32
		fallback uint32
	}{
		{&p.pre, defaultMaxPreAuth}, {&p.preIP, defaultMaxPreAuthPerIP},
		{&p.relayIP, defaultMaxRelaysPerIP}, {&p.rate, defaultRatePerIP}, {&p.burst, defaultBurstPerIP},
	} {
		if *v.value == 0 {
			*v.value = v.fallback
		}
	}
	return p
}

func (c *Config) admission() *admissionLimiter {
	return admissionPolicies.lookup(c.admissionPolicy(), time.Now())
}

func (r *admissionRegistry) lookup(p admissionPolicy, now time.Time) *admissionLimiter {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(now)
	if r.entries == nil {
		r.entries = make(map[admissionPolicy]*admissionLimiter)
	}
	a := r.entries[p]
	if a == nil {
		a = newAdmissionLimiter(p, admissionSources, time.Now)
		a.lastAcquire = now
		a.registry = r
		r.entries[p] = a
	}
	if r.stop == nil {
		r.stop, r.done = make(chan struct{}), make(chan struct{})
		go r.janitor(r.stop, r.done)
	}
	return a
}

func (r *admissionRegistry) janitor(stop, done chan struct{}) {
	defer close(done)
	ticks := r.ticks
	if ticks == nil {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		ticks = ticker.C
	}
	for {
		select {
		case <-stop:
			return
		case now := <-ticks:
			r.sweep(now)
		}
	}
}

func (r *admissionRegistry) expireLocked(now time.Time) {
	for p, a := range r.entries {
		a.mu.Lock()
		if now.Sub(a.lastAcquire) >= admissionIdle {
			delete(r.entries, p)
			a.retired = true
			a.buckets = make(map[netip.Addr]*list.Element)
			a.credits = make(map[netip.Addr]*list.Element)
			a.lru.Init()
			a.creditLRU.Init()
		}
		a.mu.Unlock()
	}
}

func (r *admissionRegistry) stopEmptyLocked() {
	if len(r.entries) == 0 && r.stop != nil {
		close(r.stop)
		r.stop = nil
	}
}

func (r *admissionRegistry) sweep(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(now)
	r.stopEmptyLocked()
}

func (r *admissionRegistry) Delete(p admissionPolicy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, p)
	r.stopEmptyLocked()
}

func parseTrustedSource(s string) (netip.Prefix, error) {
	if ip, err := netip.ParseAddr(s); err == nil && ip.Zone() == "" {
		ip = ip.Unmap()
		return netip.PrefixFrom(ip, ip.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid HMC trusted source: expected IP, CIDR or unix")
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 104 {
			return netip.Prefix{}, fmt.Errorf("HMC mapped trusted prefix requires at least 8 IPv4 bits")
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	minimum := 32
	if p.Addr().Is4() {
		minimum = 8
	}
	if p.Bits() < minimum {
		return netip.Prefix{}, fmt.Errorf("HMC trusted prefix requires at least /%d", minimum)
	}
	return p.Masked(), nil
}

func (c *Config) normalizedTrustedSources() ([]string, error) {
	if len(c.TrustedSources) > MaxTrustedSources {
		return nil, fmt.Errorf("HMC trustedSources accepts at most %d entries", MaxTrustedSources)
	}
	seen := make(map[string]bool, len(c.TrustedSources))
	var sources []string
	for _, s := range c.TrustedSources {
		if s != "unix" {
			p, err := parseTrustedSource(s)
			if err != nil {
				return nil, err
			}
			s = p.String()
		}
		if !seen[s] {
			seen[s] = true
			sources = append(sources, s)
		}
	}
	sort.Strings(sources)
	return sources, nil
}

func (c *Config) ValidateAdmission() error {
	for _, v := range []uint32{c.MaxPreAuth, c.MaxPreAuthPerIp, c.MaxRelaysPerIp, c.RatePerIp, c.BurstPerIp} {
		if v > MaxAdmissionLimit {
			return fmt.Errorf("HMC admission limits must be 0 (default) to %d", MaxAdmissionLimit)
		}
	}
	if c.MaxPreAuth > 0 && c.MaxPreAuth < 8 {
		return fmt.Errorf("HMC maxPreAuth must be 0 (default) or at least 8")
	}
	_, err := c.normalizedTrustedSources()
	return err
}

func admissionIP(addr net.Addr) netip.Addr {
	var ip netip.Addr
	if tcp, ok := addr.(*net.TCPAddr); ok {
		ip, _ = netip.AddrFromSlice(tcp.IP)
	} else if addr != nil && (addr.Network() == "tcp" || addr.Network() == "tcp4" || addr.Network() == "tcp6") {
		host, _, err := net.SplitHostPort(addr.String())
		if err == nil {
			ip, _ = netip.ParseAddr(host)
		}
	}
	return ip.Unmap().WithZone("")
}

func sourceBucket(ip netip.Addr) netip.Addr {
	ip = ip.Unmap().WithZone("")
	if ip.Is6() {
		ip = netip.PrefixFrom(ip, 64).Masked().Addr()
	}
	return ip
}

func admissionSource(addr net.Addr) netip.Addr { return sourceBucket(admissionIP(addr)) }

func aggregateSource(ip netip.Addr) netip.Addr {
	if ip.Is4() {
		return netip.PrefixFrom(ip, 24).Masked().Addr()
	}
	if ip.Is6() {
		return netip.PrefixFrom(ip, 48).Masked().Addr()
	}
	return ip
}

type admissionBucket struct {
	source netip.Addr
	at     time.Time
	tokens float64
}

type admissionLimiter struct {
	mu                             sync.Mutex
	policy                         admissionPolicy
	now                            func() time.Time
	capacity                       int
	pre, uncredited, nontrusted    int
	pendingIP                      map[netip.Addr]int
	pendingOldest, pendingNewest   *admissionLease
	preIP, relays, aggregates      map[netip.Addr]int
	creditedAggregates             map[netip.Addr]int
	buckets, credits               map[netip.Addr]*list.Element
	lru, creditLRU                 list.List
	oldest, newest                 *admissionLease
	creditedOldest, creditedNewest *admissionLease
	trusted                        []netip.Prefix
	trustedUnix                    bool
	lastAcquire                    time.Time
	registry                       *admissionRegistry
	retired                        bool
}

func newAdmissionLimiter(p admissionPolicy, capacity int, now func() time.Time) *admissionLimiter {
	a := &admissionLimiter{policy: p, capacity: capacity, now: now, lastAcquire: now(),
		preIP: make(map[netip.Addr]int), relays: make(map[netip.Addr]int), aggregates: make(map[netip.Addr]int), pendingIP: make(map[netip.Addr]int),
		creditedAggregates: make(map[netip.Addr]int), buckets: make(map[netip.Addr]*list.Element), credits: make(map[netip.Addr]*list.Element)}
	if p.trusted != "" {
		for _, s := range strings.Split(p.trusted, "\x00") {
			if s == "unix" {
				a.trustedUnix = true
			} else if prefix, err := parseTrustedSource(s); err == nil {
				a.trusted = append(a.trusted, prefix)
			}
		}
	}
	return a
}

type admissionLease struct {
	limiter                           *admissionLimiter
	source                            netip.Addr
	at                                time.Time
	conn                              net.Conn
	previous, next                    *admissionLease
	queued, released, exempt, evicted bool
	credited, pending, trusted        bool
	slot                              *knockSlot
}

func (a *admissionLimiter) isTrusted(source netip.Addr) bool {
	if !source.IsValid() {
		return a.trustedUnix
	}
	for _, p := range a.trusted {
		if p.Contains(source) {
			return true
		}
	}
	return false
}

func (a *admissionLimiter) credited(source netip.Addr, now time.Time) bool {
	e := a.credits[source]
	if e == nil {
		return false
	}
	if now.Sub(e.Value.(*admissionBucket).at) >= admissionIdle {
		delete(a.credits, source)
		a.creditLRU.Remove(e)
		return false
	}
	return true
}

func (a *admissionLimiter) acquire(source netip.Addr, connection ...net.Conn) *admissionLease {
	source = source.Unmap().WithZone("")
	a.mu.Lock()
	now := a.now()
	if a.retired {
		a.mu.Unlock()
		return a.registry.lookup(a.policy, now).acquire(source, connection...)
	}
	trusted := a.isTrusted(source)
	source = sourceBucket(source)
	a.lastAcquire = now
	credited := !trusted && a.credited(source, now)
	exempt := trusted || credited
	capIP := int(a.policy.preIP)
	if credited {
		capIP = max(int(a.policy.pre)/8, capIP)
	}
	allowed := exempt || a.allowRate(source, now)
	allowed = allowed && (trusted || a.preIP[source] < capIP)
	aggregate := aggregateSource(source)
	aggregateCap := 512
	if source.Is6() {
		aggregateCap = 256
	}
	reserve := max(1, int(a.policy.pre)/4)
	if (!exempt && a.aggregates[aggregate] >= aggregateCap) || (credited && a.creditedAggregates[aggregate] >= reserve) {
		allowed = false
	}
	var evicted net.Conn
	uncreditedCap := int(a.policy.pre) - reserve
	quotaFull := !exempt && a.uncredited >= uncreditedCap
	trustedFull := !trusted && a.nontrusted >= int(a.policy.pre)-max(1, int(a.policy.pre)/10)
	if allowed && (quotaFull || trustedFull || a.pre >= int(a.policy.pre)) {
		oldest := a.oldest
		if !a.evictable(oldest, now) && !quotaFull {
			oldest = a.creditedOldest
		}
		if !a.evictable(oldest, now) {
			oldest = a.pendingOldest
			for oldest != nil && ((quotaFull && oldest.exempt) || (trustedFull && oldest.trusted)) {
				oldest = oldest.next
			}
		}
		if a.evictable(oldest, now) {
			oldest.evicted = true
			evicted = oldest.conn
			oldest.releaseLocked()
		} else {
			allowed = false
		}
	}
	if allowed && a.pre < int(a.policy.pre) {
		l := &admissionLease{limiter: a, source: source, at: now, exempt: exempt, credited: credited, trusted: trusted}
		if len(connection) != 0 {
			l.conn = connection[0]
		}
		a.pre++
		if !trusted {
			a.nontrusted++
		}
		a.preIP[source]++
		if !exempt {
			a.uncredited++
			a.aggregates[aggregate]++
		}
		if credited {
			a.creditedAggregates[aggregate]++
		}
		if !trusted {
			l.enqueueLocked()
		}
		a.mu.Unlock()
		if evicted != nil {
			_ = evicted.Close()
		}
		return l
	}
	a.mu.Unlock()
	if evicted != nil {
		_ = evicted.Close()
	}
	admissionWarnings.reject(now)
	return nil
}

func (a *admissionLimiter) evictable(l *admissionLease, now time.Time) bool {
	if l == nil || l.conn == nil {
		return false
	}
	wait := admissionEvictWait
	if l.pending {
		wait = admissionProofWait
	}
	return now.Sub(l.at) > wait
}

func (l *admissionLease) queueLocked() (**admissionLease, **admissionLease) {
	if l.pending {
		return &l.limiter.pendingOldest, &l.limiter.pendingNewest
	}
	if l.credited {
		return &l.limiter.creditedOldest, &l.limiter.creditedNewest
	}
	return &l.limiter.oldest, &l.limiter.newest
}

func (l *admissionLease) dequeueLocked() {
	if !l.queued {
		return
	}
	oldest, newest := l.queueLocked()
	if l.previous == nil {
		*oldest = l.next
	} else {
		l.previous.next = l.next
	}
	if l.next == nil {
		*newest = l.previous
	} else {
		l.next.previous = l.previous
	}
	l.previous, l.next, l.queued = nil, nil, false
}

func (l *admissionLease) enqueueLocked() {
	oldest, newest := l.queueLocked()
	l.queued, l.previous = true, *newest
	if *newest == nil {
		*oldest = l
	} else {
		(*newest).next = l
	}
	*newest = l
}

func (l *admissionLease) postKnock(slots ...*knockSlot) bool {
	if l == nil {
		return true
	}
	a := l.limiter
	a.mu.Lock()
	defer a.mu.Unlock()
	cap := pendingPerIP
	if l.credited {
		cap = pendingCreditedPerIP
	}
	if l.released || l.pending || (!l.trusted && a.pendingIP[l.source] >= cap) {
		return false
	}
	l.dequeueLocked()
	l.pending, l.at = true, a.now()
	if len(slots) != 0 {
		l.slot = slots[0]
	}
	a.pendingIP[l.source]++
	l.enqueueLocked()
	return true
}

func (l *admissionLease) proofVerified() bool {
	if l == nil {
		return true
	}
	a := l.limiter
	a.mu.Lock()
	defer a.mu.Unlock()
	if l.released {
		return false
	}
	l.dequeueLocked()
	if l.pending {
		decrementSource(a.pendingIP, l.source)
		l.pending = false
	}
	return true
}

func (l *admissionLease) credit() {
	if l == nil {
		return
	}
	a := l.limiter
	a.mu.Lock()
	defer a.mu.Unlock()
	if l.released || a.retired {
		return
	}
	now := a.now()
	for e := a.creditLRU.Back(); e != nil && now.Sub(e.Value.(*admissionBucket).at) >= admissionIdle; e = a.creditLRU.Back() {
		delete(a.credits, e.Value.(*admissionBucket).source)
		a.creditLRU.Remove(e)
	}
	e := a.credits[l.source]
	if e == nil {
		if a.creditLRU.Len() >= a.capacity {
			oldest := a.creditLRU.Back()
			delete(a.credits, oldest.Value.(*admissionBucket).source)
			a.creditLRU.Remove(oldest)
		}
		e = a.creditLRU.PushFront(&admissionBucket{source: l.source})
		a.credits[l.source] = e
	}
	e.Value.(*admissionBucket).at = now
	a.creditLRU.MoveToFront(e)
}

func (a *admissionLimiter) allowRate(source netip.Addr, now time.Time) bool {
	for oldest := a.lru.Back(); oldest != nil; oldest = a.lru.Back() {
		if now.Sub(oldest.Value.(*admissionBucket).at) < admissionIdle {
			break
		}
		a.removeBucket(oldest)
	}
	e := a.buckets[source]
	if e == nil {
		if a.lru.Len() >= a.capacity {
			a.removeBucket(a.lru.Back())
		}
		e = a.lru.PushFront(&admissionBucket{source: source, at: now, tokens: float64(a.policy.burst)})
		a.buckets[source] = e
	}
	b := e.Value.(*admissionBucket)
	elapsed := max(0, now.Sub(b.at).Seconds())
	b.tokens = min(float64(a.policy.burst), b.tokens+elapsed*float64(a.policy.rate))
	b.at = now
	a.lru.MoveToFront(e)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (a *admissionLimiter) removeBucket(e *list.Element) {
	delete(a.buckets, e.Value.(*admissionBucket).source)
	a.lru.Remove(e)
}

func decrementSource(m map[netip.Addr]int, source netip.Addr) {
	m[source]--
	if m[source] == 0 {
		delete(m, source)
	}
}

func (l *admissionLease) releaseLocked() {
	if l.released {
		return
	}
	l.released = true
	a := l.limiter
	a.pre--
	if !l.trusted {
		a.nontrusted--
	}
	if l.pending {
		decrementSource(a.pendingIP, l.source)
	}
	l.slot.release()
	decrementSource(a.preIP, l.source)
	if !l.exempt {
		a.uncredited--
		decrementSource(a.aggregates, aggregateSource(l.source))
	}
	if l.credited {
		decrementSource(a.creditedAggregates, aggregateSource(l.source))
	}
	l.dequeueLocked()
	l.conn = nil
}

func (l *admissionLease) release() {
	if l == nil {
		return
	}
	a := l.limiter
	a.mu.Lock()
	l.releaseLocked()
	a.mu.Unlock()
}

func (l *admissionLease) relay(client net.Conn, dest string, recorded []byte, limits relayLimits) {
	if l == nil {
		relayDest(client, dest, recorded, limits)
		return
	}
	a := l.limiter
	a.mu.Lock()
	if l.evicted {
		a.mu.Unlock()
		return
	}
	if a.relays[l.source] >= int(a.policy.relayIP) {
		a.mu.Unlock()
		admissionWarnings.reject(a.now())
		return
	}
	a.relays[l.source]++
	a.mu.Unlock()
	defer func() { a.mu.Lock(); decrementSource(a.relays, l.source); a.mu.Unlock() }()
	relayDest(client, dest, recorded, limits)
}

type admissionWarning struct {
	mu       sync.Mutex
	last     time.Time
	rejected uint64
}

var admissionWarnings admissionWarning

func (w *admissionWarning) reject(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rejected++
	if !w.last.IsZero() && now.Sub(w.last) < time.Minute {
		return
	}
	errors.LogWarning(context.Background(), "HMC admission limit reached: ", w.rejected, " connections rejected")
	w.last, w.rejected = now, 0
}
