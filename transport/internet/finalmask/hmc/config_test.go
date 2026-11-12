package hmc

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func TestConfigOnlyServerWrapperStartsDestProbe(t *testing.T) {
	fake := onlineDest(t, 1)
	profile := testLoginProfile("test_user")
	config := &Config{Dest: fake.address(), Password: testPassword, CamouflagePublicKey: testPublicKey(t), Profiles: []*Profile{{Username: profile.Username, Uuid: profile.UUID[:]}}}
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	client, err := config.WrapConnClient(raw, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	time.Sleep(50 * time.Millisecond)
	if len(fake.snapshots()) != 0 {
		t.Fatal("client wrapper probed dest")
	}
	server, err := config.WrapConnServer(peer)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	waitDest(t, fake.address())
	if len(fake.snapshots()) != 2 {
		t.Fatal("server wrapper did not lazily start paired probes")
	}
}

func TestConfigRejectsInvalidPassword(t *testing.T) {
	for _, size := range []int{0, 31, 1025} {
		config := &Config{Password: strings.Repeat("p", size)}
		for _, wrap := range []func(net.Conn) (net.Conn, error){func(c net.Conn) (net.Conn, error) { return config.WrapConnClient(c, nil, nil) }, config.WrapConnServer} {
			if _, err := wrap(nil); err == nil || !strings.Contains(err.Error(), "password must be 32 to 1024 bytes") {
				t.Fatalf("password length %d: expected runtime validation, got %v", size, err)
			}
		}
	}
}

func TestConfigAcceptsPasswordBounds(t *testing.T) {
	profile := testLoginProfile("test_user")
	for _, size := range []int{32, 113, 1024} {
		config := &Config{Password: strings.Repeat("p", size), CamouflagePublicKey: testPublicKey(t), Profiles: []*Profile{{Username: profile.Username, Uuid: profile.UUID[:]}}}
		for _, wrap := range []func(net.Conn) (net.Conn, error){func(c net.Conn) (net.Conn, error) { return config.WrapConnClient(c, nil, nil) }, config.WrapConnServer} {
			a, b := net.Pipe()
			wrapped, err := wrap(a)
			if wrapped != nil {
				wrapped.Close()
			}
			a.Close()
			b.Close()
			if err != nil {
				t.Fatalf("length %d: %v", size, err)
			}
		}
	}
}

// Exercise the public protobuf/manager path, not just the internal constructors.
func TestConfigFullDuplex(t *testing.T) {
	const password = "test-only-password-32-bytes-minimum"
	publicKey := testPublicKey(t)
	profile := testLoginProfile("test_user")
	config := &Config{
		Password: password, Hostname: "localhost", CamouflagePublicKey: publicKey,
		Profiles: []*Profile{{Username: profile.Username, Uuid: profile.UUID[:]}},
	}
	message, err := serial.ToTypedMessage(config).GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	manager, ok := message.(finalmask.TCPMask)
	if !ok {
		t.Fatalf("registered config %T does not implement TCPMask", message)
	}

	certificate, err := cert.Generate(nil, cert.DNSNames("localhost"))
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := certificate.ToPEM()
	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to load test CA")
	}

	for _, withTLS := range []bool{false, true} {
		for _, network := range []string{"pipe", "tcp"} {
			t.Run(fmt.Sprintf("%s/TLS=%t", network, withTLS), func(t *testing.T) {
				var clientRaw, serverRaw net.Conn
				if network == "pipe" {
					clientRaw, serverRaw = net.Pipe()
				} else {
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					clientRaw, err = net.Dial("tcp", listener.Addr().String())
					if err != nil {
						t.Fatal(err)
					}
					serverRaw, err = listener.Accept()
					if err != nil {
						clientRaw.Close()
						t.Fatal(err)
					}
				}
				defer clientRaw.Close()
				defer serverRaw.Close()
				deadline := time.Now().Add(10 * time.Second)
				if err := clientRaw.SetDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				if err := serverRaw.SetDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				client, err := manager.WrapConnClient(clientRaw, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				server, err := manager.WrapConnServer(serverRaw)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				defer server.Close()
				server.(*serverConn).knocks = newReplayCache(16, 2*time.Minute)
				if network == "pipe" && withTLS {
					ready := make(chan error, 1)
					go func() { ready <- server.(*serverConn).handshake() }()
					if err := client.(*clientConn).handshake(); err != nil {
						t.Fatal(err)
					}
					if err := client.(*clientConn).validateLogin(); err != nil {
						t.Fatal(err)
					}
					if err := <-ready; err != nil {
						t.Fatal(err)
					}
				}
				if withTLS {
					client = tls.Client(client, &tls.Config{ServerName: "localhost", RootCAs: roots, MinVersion: tls.VersionTLS12})
					server = tls.Server(server, &tls.Config{Certificates: []tls.Certificate{keyPair}, MinVersion: tls.VersionTLS12})
					// Finish TLS before starting concurrent reads/writes at both ends.
					done := make(chan error, 1)
					go func() { done <- server.(*tls.Conn).Handshake() }()
					clientErr := client.(*tls.Conn).Handshake()
					serverErr := <-done
					if clientErr != nil || serverErr != nil {
						t.Fatalf("TLS handshake: client=%v server=%v", clientErr, serverErr)
					}
				}

				// Each plain write crosses the HMC packet boundary; different payloads
				// also catch accidental shared state between encryption directions.
				request := bytes.Repeat([]byte("request"), maxPacketData/7+123)
				response := bytes.Repeat([]byte("response"), maxPacketData/8+321)
				done := make(chan error, 4)
				for _, direction := range []struct {
					writer, reader net.Conn
					payload        []byte
				}{{client, server, request}, {server, client, response}} {
					go func(w io.Writer, payload []byte) {
						n, err := w.Write(payload)
						if err == nil && n != len(payload) {
							err = io.ErrShortWrite
						}
						done <- err
					}(direction.writer, direction.payload)
					go func(r io.Reader, payload []byte) {
						got := make([]byte, len(payload))
						_, err := io.ReadFull(r, got)
						if err == nil && !bytes.Equal(got, payload) {
							err = fmt.Errorf("full duplex payload mismatch")
						}
						done <- err
					}(direction.reader, direction.payload)
				}
				for range 4 {
					if err := <-done; err != nil {
						t.Errorf("full duplex transfer: %v", err)
					}
				}
			})
		}
	}
}
