package hmc

import (
	"net"
	"testing"
	"time"
)

func BenchmarkAdmissionPolicyAccept(b *testing.B) {
	c := admissionConfig(b)
	a := c.admission()
	now := time.Now()
	a.now = func() time.Time { now = now.Add(time.Millisecond); return now }
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		lease := c.admission().acquire(admissionSource(remote))
		if lease == nil {
			b.Fatal("unexpected rejection")
		}
		lease.release()
	}
}
