package tcp_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/hmc"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tcp"
)

func hmcListener(t *testing.T, cfg *hmc.Config, proxyProtocol bool, onConn func(stat.Connection)) string {
	t.Helper()
	sc := &internet.StreamConfig{
		ProtocolName:      "tcp",
		TransportSettings: []*internet.TransportConfig{{ProtocolName: "tcp", Settings: serial.ToTypedMessage(&tcp.Config{})}},
		Tcpmasks:          []*serial.TypedMessage{serial.ToTypedMessage(cfg)},
	}
	if proxyProtocol {
		sc.SocketSettings = &internet.SocketConfig{AcceptProxyProtocol: true}
	}
	mss, err := internet.ToMemoryStreamConfig(sc)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	l, err := tcp.ListenTCP(context.Background(), xnet.ParseAddress("127.0.0.1"), xnet.Port(port), mss, onConn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
}

func hmcPassword(t *testing.T) string {
	return "0123456789abcdef0123456789abcdef-" + t.Name() + time.Now().String()
}

func dialFrom(t *testing.T, src, dst string) net.Conn {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 5 * time.Second}
	c, err := d.Dial("tcp", dst)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// An over-limit source must not slow accepts for anyone else: the listener loop
// sleeps after an Accept error, so admission must not surface from Accept.
func TestHMCAdmissionRejectionDoesNotStallListener(t *testing.T) {
	victim := make(chan time.Time, 1)
	addr := hmcListener(t, &hmc.Config{Password: hmcPassword(t), CamouflagePublicKey: []byte{1}, RatePerIp: 1, BurstPerIp: 1}, false, func(c stat.Connection) {
		if c.RemoteAddr().(*net.TCPAddr).IP.String() == "127.0.0.3" {
			victim <- time.Now()
		}
	})
	for range 30 {
		dialFrom(t, "127.0.0.2", addr)
	}
	start := time.Now()
	dialFrom(t, "127.0.0.3", addr)
	select {
	case at := <-victim:
		if elapsed := at.Sub(start); elapsed > 500*time.Millisecond {
			t.Fatalf("accept of an unrelated source took %v behind 29 rejected connections", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("unrelated source was never accepted")
	}
}

// The PROXY header is read lazily on RemoteAddr(); the mask must not call it inside Accept.
func TestHMCDoesNotBlockAcceptOnIdleProxyProtocolConn(t *testing.T) {
	got := make(chan string, 4)
	addr := hmcListener(t, &hmc.Config{Password: hmcPassword(t), CamouflagePublicKey: []byte{1}}, true, func(c stat.Connection) {
		got <- c.RemoteAddr().String()
	})
	idle := dialFrom(t, "127.0.0.1", addr)
	_ = idle
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	victim := dialFrom(t, "127.0.0.1", addr)
	if _, err := victim.Write([]byte("PROXY TCP4 198.51.100.7 127.0.0.1 1111 2222\r\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(3 * time.Second)
	for {
		select {
		case remote := <-got:
			if remote != "198.51.100.7:1111" {
				continue
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("accept waited %v behind an idle PROXY-protocol connection", elapsed)
			}
			return
		case <-deadline:
			t.Fatal("connection behind an idle PROXY-protocol connection was not accepted in time")
		}
	}
}
