package tls

import (
	gotls "crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

func TestCertificateFileReloadIsVisible(t *testing.T) {
	original, _ := cert.MustGenerate(nil, cert.DNSNames("old.test.invalid"))
	replacement, _ := cert.MustGenerate(nil, cert.DNSNames("new.test.invalid"))
	originalPEM, originalKey := original.ToPEM()
	replacementPEM, replacementKey := replacement.ToPEM()
	dir := t.TempDir()
	certificatePath, keyPath := filepath.Join(dir, "test-cert.pem"), filepath.Join(dir, "test-key.pem")
	if err := os.WriteFile(certificatePath, replacementPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, replacementKey, 0o600); err != nil {
		t.Fatal(err)
	}
	entry := &Certificate{Certificate: originalPEM, Key: originalKey, CertificatePath: certificatePath, KeyPath: keyPath}
	config := (&Config{Certificate: []*Certificate{entry}, RejectUnknownSni: true}).GetTLSConfig()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if selected, err := config.GetCertificate(&gotls.ClientHelloInfo{ServerName: "new.test.invalid"}); err == nil && selected.Leaf.VerifyHostname("new.test.invalid") == nil {
			if string(entry.Certificate) != string(originalPEM) {
				t.Fatal("reload mutated shared protobuf configuration")
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("reloaded certificate was not published to new handshakes")
}

func TestCertificateSelectionSeesReplacement(t *testing.T) {
	old := &gotls.Certificate{Leaf: &x509.Certificate{DNSNames: []string{"old.test.invalid"}}}
	next := &gotls.Certificate{Leaf: &x509.Certificate{DNSNames: []string{"new.test.invalid"}}}
	certificates := []*gotls.Certificate{old}
	get := getNewGetCertificateFunc(certificates, true)
	if found, err := get(&gotls.ClientHelloInfo{ServerName: "old.test.invalid"}); err != nil || found != old {
		t.Fatal("initial certificate missing")
	}
	certificates[0] = next
	if found, err := get(&gotls.ClientHelloInfo{ServerName: "new.test.invalid"}); err != nil || found != next {
		t.Fatal("certificate replacement remained invisible to SNI lookup")
	}
	if _, err := get(&gotls.ClientHelloInfo{ServerName: "old.test.invalid"}); err == nil {
		t.Fatal("replaced certificate name remained accepted")
	}
}

func TestCertificateSelectionRejectsEmptySNI(t *testing.T) {
	certificate := &gotls.Certificate{Leaf: &x509.Certificate{DNSNames: []string{"test.invalid"}}}
	get := getNewGetCertificateFunc([]*gotls.Certificate{certificate}, true)
	if _, err := get(&gotls.ClientHelloInfo{}); err == nil {
		t.Fatal("empty SNI bypassed rejectUnknownSNI")
	}
}

func TestCertificateSelectionPreservesFirstMatch(t *testing.T) {
	first := &gotls.Certificate{Leaf: &x509.Certificate{DNSNames: []string{"test.invalid"}}}
	second := &gotls.Certificate{Leaf: &x509.Certificate{DNSNames: []string{"test.invalid"}}}
	get := getNewGetCertificateFunc([]*gotls.Certificate{first, second}, true)
	if found, err := get(&gotls.ClientHelloInfo{ServerName: "test.invalid"}); err != nil || found != first {
		t.Fatal("duplicate SNI changed certificate priority")
	}
}
