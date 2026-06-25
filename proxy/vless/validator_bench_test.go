package vless

import (
	"strconv"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

func benchmarkValidatorGetN(b *testing.B, n int) {
	v := &MemoryValidator{}
	ids := make([]uuid.UUID, n)
	for i := 0; i < n; i++ {
		id := uuid.New()
		ids[i] = id
		u := &protocol.MemoryUser{
			Email: "user" + strconv.Itoa(i) + "@example.com",
			Account: &MemoryAccount{
				ID: protocol.NewID(id),
			},
		}
		if err := v.Add(u); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.Get(ids[i%n])
	}
}

func BenchmarkValidatorGet1(b *testing.B)     { benchmarkValidatorGetN(b, 1) }
func BenchmarkValidatorGet10(b *testing.B)    { benchmarkValidatorGetN(b, 10) }
func BenchmarkValidatorGet100(b *testing.B)   { benchmarkValidatorGetN(b, 100) }
func BenchmarkValidatorGet1000(b *testing.B)  { benchmarkValidatorGetN(b, 1000) }
func BenchmarkValidatorGet10000(b *testing.B) { benchmarkValidatorGetN(b, 10000) }
