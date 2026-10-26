package trojan

import (
	"encoding/hex"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

func TestWireKeyMatchesLegacyLookup(t *testing.T) {
	v := NewValidator()
	key := hexSha224("TEST")
	user := &protocol.MemoryUser{Email: "TEST", Account: &MemoryAccount{Key: key}}
	if err := v.Add(user); err != nil {
		t.Fatal(err)
	}
	wrong := append([]byte(nil), key...)
	wrong[0] ^= 1
	upper := append([]byte(nil), key...)
	for i, ch := range upper {
		if ch >= 'a' && ch <= 'f' {
			upper[i] = ch - ('a' - 'A')
			break
		}
	}
	for name, probe := range map[string][]byte{"valid": key, "wrong": wrong, "uppercase": upper} {
		t.Run(name, func(t *testing.T) {
			got := v.GetByKey(probe)
			want := v.Get(hex.EncodeToString(probe))
			if got != want {
				t.Fatal("wire lookup differs from legacy authentication")
			}
			if name == "valid" && got != user {
				t.Fatal("valid test credential rejected")
			}
			if name != "valid" && got != nil {
				t.Fatal("invalid test credential accepted")
			}
		})
	}
	for _, probe := range [][]byte{nil, key[:55], append(append([]byte(nil), key...), 0)} {
		if v.GetByKey(probe) != nil {
			t.Fatal("invalid wire-key length accepted")
		}
	}
	if err := v.Del("TEST"); err != nil {
		t.Fatal(err)
	}
	if v.GetByKey(key) != nil {
		t.Fatal("revoked test credential remained valid")
	}
	if err := v.Add(user); err != nil {
		t.Fatal(err)
	}
	reused := append([]byte(nil), key...)
	if v.GetByKey(reused) != user {
		t.Fatal("re-added test credential rejected")
	}
	clear(reused)
	if v.GetByKey(key) != user {
		t.Fatal("lookup retained a mutable caller buffer")
	}
}

func TestWireLookupDoesNotAllocate(t *testing.T) {
	v := NewValidator()
	key := hexSha224("TEST")
	user := &protocol.MemoryUser{Email: "TEST", Account: &MemoryAccount{Key: key}}
	if err := v.Add(user); err != nil {
		t.Fatal(err)
	}
	var found *protocol.MemoryUser
	if allocations := testing.AllocsPerRun(100, func() { found = v.GetByKey(key) }); allocations != 0 {
		t.Fatalf("wire lookup allocated %.0f objects", allocations)
	}
	if found != user {
		t.Fatal("lookup result changed")
	}
}

func TestWireLookupDuringUpdates(t *testing.T) {
	v := NewValidator()
	key := hexSha224("TEST")
	user := &protocol.MemoryUser{Email: "TEST", Account: &MemoryAccount{Key: key}}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if err := v.Add(user); err != nil {
				t.Error(err)
				return
			}
			if err := v.Del("TEST"); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			if got := v.GetByKey(key); got != nil && got != user {
				t.Error("unexpected user returned")
			}
		}
	}()
	wg.Wait()
	if v.GetByKey(key) != nil {
		t.Fatal("final revocation lost")
	}
}
