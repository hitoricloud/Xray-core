package serial

import "testing"

func BenchmarkToStringInt(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ToString(i)
	}
}

func BenchmarkToStringInt64(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ToString(int64(i))
	}
}

func BenchmarkToStringUint32(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ToString(uint32(i))
	}
}
