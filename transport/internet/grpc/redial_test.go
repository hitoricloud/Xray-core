package grpc

import (
	"context"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	gogrpc "google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestRedialAfterInitialContextCanceled(t *testing.T) {
	start := func(address string) (*gogrpc.Server, net.Listener) {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		server := gogrpc.NewServer()
		status := health.NewServer()
		status.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
		healthpb.RegisterHealthServer(server, status)
		go server.Serve(listener)
		t.Cleanup(server.Stop)
		return server, listener
	}
	server, listener := start("127.0.0.1:0")
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	initial, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := getGrpcClient(initial, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(port)), &internet.MemoryStreamConfig{ProtocolSettings: &Config{}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	check := healthpb.NewHealthClient(conn)
	if _, err := check.Check(initial, &healthpb.HealthCheckRequest{}, gogrpc.WaitForReady(true)); err != nil {
		t.Fatal(err)
	}
	cancel()
	server.Stop()
	later, stop := context.WithTimeout(context.Background(), 4*time.Second)
	defer stop()
	// An RPC sent before the client notices the closed transport fails with EOF regardless of the dial context.
	for state := conn.GetState(); state == connectivity.Ready; state = conn.GetState() {
		if !conn.WaitForStateChange(later, state) {
			t.Fatal("client never noticed the stopped server")
		}
	}
	start(address)
	if _, err := check.Check(later, &healthpb.HealthCheckRequest{}, gogrpc.WaitForReady(true)); err != nil {
		t.Fatalf("redial retained canceled request context: %v", err)
	}
}
