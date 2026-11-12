package hmc

import (
	"testing"
	"time"
)

func TestReplayCache(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := newReplayCache(2, time.Minute)
	a, b, c := []byte("a"), []byte("b"), []byte("c")
	if !cache.firstUse(a, now) || cache.firstUse(a, now.Add(time.Second)) {
		t.Fatal("repeat inside lifetime must be rejected")
	}
	if !cache.firstUse(b, now) {
		t.Fatal("new entry rejected")
	}
	if cache.firstUse(a, now) || cache.firstUse(b, now) {
		t.Fatal("repeat evicted itself at capacity")
	}
	if !cache.firstUse(c, now) {
		t.Fatal("new responses must be accepted")
	}
	if !cache.firstUse(a, now) {
		t.Fatal("oldest entry must be evicted at capacity")
	}
	if !cache.firstUse(b, now.Add(2*time.Minute)) {
		t.Fatal("expired entry must be accepted again")
	}
	if len(cache.seen) != len(cache.order) || len(cache.order) > cache.capacity {
		t.Fatalf("cache bookkeeping diverged: %d/%d", len(cache.seen), len(cache.order))
	}
}
