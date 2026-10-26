package load

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	applog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
)

// One active loopback connection at a time, no TLS, two verified 1 KiB echoes.
func BenchmarkCompareTrojanConnectEcho(b *testing.B) {
	echo := tcp.Server{MsgProcessor: func(data []byte) []byte { return data }}
	target, err := echo.Start()
	if err != nil {
		b.Fatal(err)
	}
	defer echo.Close()
	port := tcp.PickPort()
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&applog.Config{ErrorLogLevel: log.Severity_Warning, ErrorLogType: applog.LogType_File, ErrorLogPath: os.DevNull}),
			serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound:  []*core.InboundHandlerConfig{{ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}}, Listen: net.NewIPOrDomain(net.LocalHostIP)}), ProxySettings: serial.ToTypedMessage(&trojan.ServerConfig{Users: []*protocol.User{{Account: serial.ToTypedMessage(&trojan.Account{Password: "TEST"})}}})}},
		Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}})}},
	}
	instance, err := core.New(config)
	if err != nil {
		b.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		b.Fatal(err)
	}
	defer instance.Close()
	account, err := (&trojan.Account{Password: "TEST"}).AsAccount()
	if err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 1024)
	run := func() error {
		conn, err := internet.DialSystem(context.Background(), net.TCPDestination(net.LocalHostIP, port), nil)
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			return err
		}
		writer := &trojan.ConnWriter{Writer: conn, Target: target, Account: account.(*trojan.MemoryAccount)}
		got := make([]byte, len(payload))
		for i := 0; i < 2; i++ {
			if _, err := writer.Write(payload); err != nil {
				return err
			}
			if _, err := io.ReadFull(conn, got); err != nil {
				return err
			}
			if !bytes.Equal(got, payload) {
				return io.ErrUnexpectedEOF
			}
		}
		return nil
	}
	for i := 0; i < 3; i++ {
		if err := run(); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := run(); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}
