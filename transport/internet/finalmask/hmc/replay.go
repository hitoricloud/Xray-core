package hmc

import (
	"crypto/sha256"
	"sync"
	"time"
)

// Only authenticated values enter these bounded process-local caches.
type replayCache struct {
	mu       sync.Mutex
	seen     map[[18]byte]time.Time
	order    []replayEntry
	capacity int
	lifetime time.Duration
}

type replayEntry struct {
	key [18]byte
	at  time.Time
}

var loginReplays = newReplayCache(1<<17, time.Hour)
var knockReplays = newReplayCache(1<<16, 2*time.Minute)

func newReplayCache(capacity int, lifetime time.Duration) *replayCache {
	return &replayCache{seen: make(map[[18]byte]time.Time), capacity: capacity, lifetime: lifetime}
}

// contains reports, without recording anything, whether the key was already used.
func (c *replayCache) contains(secretField []byte, now time.Time) bool {
	var key [18]byte
	if len(secretField) == len(key) {
		copy(key[:], secretField)
	} else {
		sum := sha256.Sum256(secretField)
		copy(key[:], sum[:len(key)])
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	at, ok := c.seen[key]
	return ok && now.Sub(at) < c.lifetime
}

func (c *replayCache) firstUse(secretField []byte, now time.Time) bool {
	var key [18]byte
	if len(secretField) == len(key) {
		copy(key[:], secretField)
	} else {
		sum := sha256.Sum256(secretField)
		copy(key[:], sum[:len(key)])
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.order) > 0 && (now.Sub(c.order[0].at) >= c.lifetime) {
		oldest := c.order[0]
		c.order = c.order[1:]
		if at, ok := c.seen[oldest.key]; ok && at.Equal(oldest.at) {
			delete(c.seen, oldest.key)
		}
	}
	if at, ok := c.seen[key]; ok && now.Sub(at) < c.lifetime {
		return false
	}
	if len(c.order) >= c.capacity {
		oldest := c.order[0]
		c.order = c.order[1:]
		if at, ok := c.seen[oldest.key]; ok && at.Equal(oldest.at) {
			delete(c.seen, oldest.key)
		}
	}
	c.seen[key] = now
	c.order = append(c.order, replayEntry{key: key, at: now})
	return true
}
