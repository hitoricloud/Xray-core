package scenarios

import (
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	v2http "github.com/xtls/xray-core/proxy/http"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

// Upstream 061c2df2: an HTTP outbound must receive greetings before client data.
func TestHTTPOutboundServerFirst(t *testing.T) {
	echo := tcp.Server{MsgProcessor: xor, SendFirst: []byte("TEST greeting")}
	target, err := echo.Start()
	common.Must(err)
	defer echo.Close()
	serverPort := tcp.PickPort()
	server := &core.Config{
		Inbound:  []*core.InboundHandlerConfig{{ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}}, Listen: net.NewIPOrDomain(net.LocalHostIP)}), ProxySettings: serial.ToTypedMessage(&v2http.ServerConfig{})}},
		Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}})}},
	}
	clientPort := tcp.PickPort()
	client := &core.Config{
		Inbound:  []*core.InboundHandlerConfig{{ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}}, Listen: net.NewIPOrDomain(net.LocalHostIP)}), ProxySettings: serial.ToTypedMessage(&dokodemo.Config{RewriteAddress: net.NewIPOrDomain(target.Address), RewritePort: uint32(target.Port), AllowedNetworks: []net.Network{net.Network_TCP}})}},
		Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(&v2http.ClientConfig{Server: &protocol.ServerEndpoint{Address: net.NewIPOrDomain(net.LocalHostIP), Port: uint32(serverPort)}})}},
	}
	servers, err := InitializeServerConfigs(server, client)
	common.Must(err)
	defer CloseAllServers(servers)
	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: int(clientPort)})
	common.Must(err)
	defer conn.Close()
	common.Must(conn.SetReadDeadline(time.Now().Add(3 * time.Second)))
	greeting := make([]byte, len("TEST greeting"))
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatal("no server greeting through HTTP outbound: ", err)
	}
	if string(greeting) != "TEST greeting" {
		t.Fatal("greeting changed")
	}
	if err := testTCPConn2(conn, 1024, time.Second*3)(); err != nil {
		t.Fatal(err)
	}
}
