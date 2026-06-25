package trojan

import (
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

func benchmarkValidatorGetN(b *testing.B, n int) {
	v := NewValidator()
	hashes := make([]string, n)
	for i := 0; i < n; i++ {
		key := hexSha224("password" + strconv.Itoa(i))
		hash := hex.EncodeToString(key)
		hashes[i] = hash
		u := &protocol.MemoryUser{
			Email: "user" + strconv.Itoa(i) + "@example.com",
			Account: &MemoryAccount{
				Key: key,
			},
		}
		if err := v.Add(u); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.Get(hashes[i%n])
	}
}

func BenchmarkValidatorGet1(b *testing.B)     { benchmarkValidatorGetN(b, 1) }
func BenchmarkValidatorGet10(b *testing.B)    { benchmarkValidatorGetN(b, 10) }
func BenchmarkValidatorGet100(b *testing.B)   { benchmarkValidatorGetN(b, 100) }
func BenchmarkValidatorGet1000(b *testing.B)  { benchmarkValidatorGetN(b, 1000) }
func BenchmarkValidatorGet10000(b *testing.B) { benchmarkValidatorGetN(b, 10000) }

func BenchmarkHexString(b *testing.B) {
	key := hexSha224("password123")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hexString(key)
	}
}

func BenchmarkHexEncodeToString(b *testing.B) {
	key := hexSha224("password123")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hex.EncodeToString(key)
	}
}
