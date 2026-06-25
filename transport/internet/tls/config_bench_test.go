package tls_test

import (
	gotls "crypto/tls"
	"fmt"
	"testing"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
	. "github.com/xtls/xray-core/transport/internet/tls"
)

func benchmarkCertificateLookupN(b *testing.B, n int) {
	c := &Config{
		RejectUnknownSni: true,
	}
	for i := 0; i < n; i++ {
		ct, _ := cert.MustGenerate(nil, cert.CommonName(fmt.Sprintf("host%d.example.com", i)), cert.DNSNames(fmt.Sprintf("host%d.example.com", i)))
		c.Certificate = append(c.Certificate, ParseCertificate(ct))
	}

	tlsConfig := c.GetTLSConfig()
	hello := &gotls.ClientHelloInfo{ServerName: fmt.Sprintf("host%d.example.com", n/2)}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = tlsConfig.GetCertificate(hello)
	}
}

func BenchmarkCertificateLookup10(b *testing.B)    { benchmarkCertificateLookupN(b, 10) }
func BenchmarkCertificateLookup100(b *testing.B)   { benchmarkCertificateLookupN(b, 100) }
func BenchmarkCertificateLookup1000(b *testing.B)  { benchmarkCertificateLookupN(b, 1000) }
func BenchmarkCertificateLookup10000(b *testing.B) { benchmarkCertificateLookupN(b, 10000) }
