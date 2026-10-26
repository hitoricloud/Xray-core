package hysteria

import (
	"context"
	gotls "crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestLocalHysteriaAuthentication(t *testing.T) {
	fixture, _ := cert.MustGenerate(nil, cert.DNSNames("test.invalid"))
	certificate := xtls.ParseCertificate(fixture)
	certificate.OneTimeLoading = true
	listener, err := Listen(context.Background(), xnet.LocalHostIP, 0, &internet.MemoryStreamConfig{
		ProtocolSettings: &Config{Auth: "TEST"}, SecuritySettings: &xtls.Config{Certificate: []*xtls.Certificate{certificate}},
	}, func(conn stat.Connection) { conn.Close() })
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	parsed, err := x509.ParseCertificate(fixture.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	for _, auth := range []string{"TEST", "WRONG-TEST"} {
		c := &client{lock: make(chan struct{}, 1), dest: xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(listener.Addr().(*net.UDPAddr).Port)),
			config: &Config{Auth: auth}, tlsConfig: &gotls.Config{RootCAs: roots, ServerName: "test.invalid", NextProtos: []string{"h3"}}}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err := c.tcp(ctx)
		cancel()
		if auth == "TEST" {
			if err != nil {
				t.Fatal("local authentication failed: ", err)
			}
			conn.Close()
			c.close()
		} else if err == nil {
			conn.Close()
			c.close()
			t.Fatal("wrong credential authenticated")
		}
	}
}

func TestCanceledClientDoesNotWaitForDialLock(t *testing.T) {
	c := &client{lock: make(chan struct{}, 1)}
	c.lock <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.tcp(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("TCP cancellation: %v", err)
	}
	if _, err := c.udp(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("UDP cancellation: %v", err)
	}
	c.unlock()
}

func TestHysteriaAuthHonorsCancellation(t *testing.T) {
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	addr := silent.LocalAddr().(*net.UDPAddr)
	c := &client{lock: make(chan struct{}, 1), dest: xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(addr.Port)), config: &Config{Auth: "TEST"}, tlsConfig: &gotls.Config{ServerName: "test.invalid", NextProtos: []string{"h3"}}}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	before := time.Now()
	if _, err := c.tcp(ctx); err == nil {
		t.Fatal("silent peer unexpectedly authenticated")
	}
	if elapsed := time.Since(before); elapsed > time.Second {
		t.Fatalf("authentication ignored cancellation for %v", elapsed)
	}
}

func TestCloseInterruptsStalledWrite(t *testing.T) {
	fixture, _ := cert.MustGenerate(nil, cert.DNSNames("test.invalid"))
	certPEM, keyPEM := fixture.ToPEM()
	certificate, err := gotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(fixture.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	listener, err := quic.ListenAddr("127.0.0.1:0", &gotls.Config{Certificates: []gotls.Certificate{certificate}, NextProtos: []string{"TEST"}}, &quic.Config{InitialStreamReceiveWindow: 1024, MaxStreamReceiveWindow: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, listener.Addr().String(), &gotls.Config{RootCAs: roots, ServerName: "test.invalid", NextProtos: []string{"TEST"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	peer, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c := &interConn{stream: stream, lock: make(chan struct{}, 1)}
	written := make(chan error, 1)
	go func() { _, err := c.Write(make([]byte, 1024*1024)); written <- err }()
	if _, err := peer.AcceptStream(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-written:
		t.Fatal("test write did not block on flow control")
	default:
	}
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked behind Write")
	}
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("canceled write unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("stalled Write was not interrupted")
	}
}
