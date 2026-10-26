package trojan

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

var wireLookupResult *protocol.MemoryUser

// Measures the wire-key path used by the inbound on every handshake.
func BenchmarkCompareTrojanWireLookup(b *testing.B) {
	v := NewValidator()
	key := hexSha224("TEST")
	user := &protocol.MemoryUser{Email: "TEST", Account: &MemoryAccount{Key: key}}
	if err := v.Add(user); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wireLookupResult = v.GetByKey(key)
	}
	if wireLookupResult != user {
		b.Fatal("test credential not found")
	}
}
