package buf

import "testing"

func BenchmarkNewBufferPooled(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b := New()
		b.Release()
	}
}

func BenchmarkNewBufferAllocated(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b := NewWithSize(Size)
		b.Release()
	}
}
