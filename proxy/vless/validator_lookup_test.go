package vless

import (
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

func TestLookupPreservesIdentityAndRevocation(t *testing.T) {
	v := NewMemoryValidator()
	id := uuid.New()
	user := &protocol.MemoryUser{Email: "TEST", Account: &MemoryAccount{ID: protocol.NewID(id)}}
	if err := v.Add(user); err != nil {
		t.Fatal(err)
	}
	if v.Get(id) != user {
		t.Fatal("valid test identity rejected")
	}
	routed := id
	routed[6] ^= 1
	routed[7] ^= 1
	if v.Get(routed) != user {
		t.Fatal("existing vlessRoute normalization changed")
	}
	wrong := id
	wrong[0] ^= 1
	if v.Get(wrong) != nil {
		t.Fatal("wrong test identity accepted")
	}
	if err := v.Del("TEST"); err != nil {
		t.Fatal(err)
	}
	if v.Get(id) != nil {
		t.Fatal("revoked test identity remained valid")
	}
}

func TestLookupDuringUpdates(t *testing.T) {
	v := NewMemoryValidator()
	id := uuid.New()
	user := &protocol.MemoryUser{Email: "TEST", Account: &MemoryAccount{ID: protocol.NewID(id)}}
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
			if got := v.Get(id); got != nil && got != user {
				t.Error("unexpected user returned")
			}
		}
	}()
	wg.Wait()
	if v.Get(id) != nil {
		t.Fatal("final revocation lost")
	}
}
