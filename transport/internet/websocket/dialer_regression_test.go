package websocket

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gorillaws "github.com/gorilla/websocket"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func TestDeferredAddressesDuringDial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := gorillaws.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err == nil {
			conn.Close()
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := &delayDialConn{
		dialed: make(chan bool, 1), cancel: cancel, ctx: ctx,
		dest:           xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(server.Listener.Addr().(*net.TCPAddr).Port)),
		streamSettings: &internet.MemoryStreamConfig{ProtocolSettings: &Config{Ed: 16, Path: "/"}},
	}
	done := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("x")); done <- err }()
	for {
		select {
		case err := <-done:
			defer conn.Close()
			if err != nil {
				t.Fatal(err)
			}
			if conn.LocalAddr() == nil || conn.RemoteAddr() == nil {
				t.Fatal("published connection has no addresses")
			}
			return
		case <-ctx.Done():
			t.Fatal("deferred dial did not finish")
		default:
			conn.LocalAddr()
			conn.RemoteAddr()
		}
	}
}

func TestDeferredCloseDuringDial(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		upgrader := gorillaws.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err == nil {
			conn.Close()
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := &delayDialConn{
		dialed: make(chan bool, 1), cancel: cancel, ctx: ctx,
		dest:           xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(server.Listener.Addr().(*net.TCPAddr).Port)),
		streamSettings: &internet.MemoryStreamConfig{ProtocolSettings: &Config{Ed: 16, Path: "/"}},
	}
	done := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("x")); done <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		close(release)
		t.Fatal("deferred dial did not reach handshake")
	}
	if err := conn.Close(); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed deferred connection accepted a write")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("closed dial did not finish")
	}
	if published, closed := conn.connectionState(); published != nil || !closed {
		t.Fatal("connection published after Close")
	}
}

func TestDeferredAddressesBeforeDial(t *testing.T) {
	conn := &delayDialConn{}
	if conn.LocalAddr() != nil || conn.RemoteAddr() != nil {
		t.Fatal("addresses must be unavailable before dial")
	}
	for _, set := range []func(time.Time) error{conn.SetDeadline, conn.SetReadDeadline, conn.SetWriteDeadline} {
		if !errors.Is(set(time.Now()), io.ErrClosedPipe) {
			t.Fatal("predial deadline must fail without panic")
		}
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn.Conn = left
	if conn.LocalAddr() != left.LocalAddr() || conn.RemoteAddr() != left.RemoteAddr() {
		t.Fatal("established addresses not forwarded")
	}
	for _, set := range []func(time.Time) error{conn.SetDeadline, conn.SetReadDeadline, conn.SetWriteDeadline} {
		if err := set(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
}
