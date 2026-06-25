package uuid

import "testing"

func BenchmarkUUIDString(b *testing.B) {
	u := New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = u.String()
	}
}
