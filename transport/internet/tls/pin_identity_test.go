package tls

import (
	gotls "crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

func TestPinnedCARequiresServerIdentity(t *testing.T) {
	ca, hash := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	leaf, _ := cert.MustGenerate(ca, cert.DNSNames("test.invalid"))
	raw := [][]byte{leaf.Certificate, ca.Certificate}
	carrier := &RandCarrier{Config: &gotls.Config{}, PinnedPeerCertSha256: [][]byte{hash[:]}}
	if err := carrier.verifyPeerCert(raw, nil); err == nil {
		t.Fatal("CA pin accepted without a server identity")
	}
	carrier.Config.ServerName = "wrong.invalid"
	if err := carrier.verifyPeerCert(raw, nil); err == nil {
		t.Fatal("CA pin accepted a wrong server identity")
	}
	carrier.Config.ServerName = "test.invalid"
	if err := carrier.verifyPeerCert(raw, nil); err != nil {
		t.Fatal(err)
	}
}
