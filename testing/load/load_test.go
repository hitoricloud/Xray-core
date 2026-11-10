package load

import (
	"context"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/proxy/vless/inbound"
	tcpserver "github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/udp"

	_ "github.com/xtls/xray-core/main/distro/all"
)

func BenchmarkVlessLoad(b *testing.B) {
	// Suppress log output during the benchmark.
	clog.RegisterHandler(&discardHandler{})

	// TCP echo server.
	server := tcpserver.Server{MsgProcessor: xor}
	dest, err := server.Start()
	common.Must(err)
	defer server.Close()

	userID := protocol.NewID(uuid.New())
	serverPort := tcpserver.PickPort()
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Warning,
				ErrorLogType:  log.LogType_Console,
			}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					Users: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vless.Account{
								Id: userID.String(),
							}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}

	inst, err := core.New(cfg)
	common.Must(err)
	common.Must(inst.Start())
	defer inst.Close()

	vlessAddr := net.TCPDestination(net.LocalHostIP, serverPort)
	account := &vless.MemoryAccount{ID: userID}
	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    &protocol.MemoryUser{Account: account},
		Command: protocol.RequestCommandTCP,
		Address: dest.Address,
		Port:    dest.Port,
	}
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}

	// Warm-up.
	for i := 0; i < 3; i++ {
		runConn(vlessAddr, account, request, payload)
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := runConn(vlessAddr, account, request, payload); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	b.Logf("heap growth per conn: %.1f B, live heap: %d", float64(after.HeapAlloc-before.HeapAlloc)/float64(b.N), after.HeapAlloc)
}

func runConn(dest net.Destination, account *vless.MemoryAccount, request *protocol.RequestHeader, payload []byte) error {
	conn, err := openConn(dest, account, request, payload)
	if err != nil {
		return err
	}
	defer conn.Close()
	return runRoundTrip(conn, payload)
}

// openConn establishes a VLESS connection and completes the first handshake
// by sending the request header + payload, then reading the response header.
// The server buffers the response header until it has data to write back.
func openConn(dest net.Destination, account *vless.MemoryAccount, request *protocol.RequestHeader, payload []byte) (net.Conn, error) {
	conn, err := internet.DialSystem(context.Background(), dest, nil)
	if err != nil {
		return nil, err
	}
	if err := encoding.EncodeRequestHeader(conn, request, &encoding.Addons{}); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write(payload); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := encoding.DecodeResponseHeader(conn, request); err != nil {
		conn.Close()
		return nil, err
	}
	// Read the first echo response too.
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		conn.Close()
		return nil, err
	}
	for i := range payload {
		if got[i] != (payload[i] ^ 'c') {
			conn.Close()
			return nil, errors.New("echo mismatch at byte ", i)
		}
	}
	return conn, nil
}

func runRoundTrip(conn net.Conn, payload []byte) error {
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	for i := range payload {
		if got[i] != (payload[i] ^ 'c') {
			return errors.New("echo mismatch at byte ", i)
		}
	}
	return nil
}

func xor(b []byte) []byte {
	r := make([]byte, len(b))
	for i, v := range b {
		r[i] = v ^ 'c'
	}
	return r
}

func BenchmarkVlessConcurrent500(b *testing.B) {
	clog.RegisterHandler(&discardHandler{})

	server := tcpserver.Server{MsgProcessor: xor}
	dest, err := server.Start()
	common.Must(err)
	defer server.Close()

	userID := protocol.NewID(uuid.New())
	serverPort := tcpserver.PickPort()
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Warning,
				ErrorLogType:  log.LogType_Console,
			}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					Users: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vless.Account{
								Id: userID.String(),
							}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}

	inst, err := core.New(cfg)
	common.Must(err)
	common.Must(inst.Start())
	defer inst.Close()

	vlessAddr := net.TCPDestination(net.LocalHostIP, serverPort)
	account := &vless.MemoryAccount{ID: userID}
	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    &protocol.MemoryUser{Account: account},
		Command: protocol.RequestCommandTCP,
		Address: dest.Address,
		Port:    dest.Port,
	}
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}

	// Warm-up a few connections.
	for i := 0; i < 10; i++ {
		if err := runConn(vlessAddr, account, request, payload); err != nil {
			b.Fatal(err)
		}
	}

	// Open 500 long-lived connections sequentially to avoid thundering herd.
	const concurrency = 500
	conns := make([]net.Conn, concurrency)
	for i := 0; i < concurrency; i++ {
		c, err := openConn(vlessAddr, account, request, payload)
		if err != nil {
			b.Fatal(err)
		}
		conns[i] = c
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	b.ResetTimer()
	b.ReportAllocs()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	var ops int64
	for i := range conns {
		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := runRoundTrip(conn, payload); err != nil {
					b.Error(err)
					return
				}
				atomic.AddInt64(&ops, 1)
			}
		}(conns[i])
	}

	time.Sleep(10 * time.Second)
	close(stop)
	wg.Wait()

	b.StopTimer()
	b.N = int(ops)
	b.Logf("500 concurrent users: %d ops over 10s, %.0f ops/s", ops, float64(ops)/10.0)
}

type discardHandler struct{}

func (discardHandler) Handle(clog.Message) {}
