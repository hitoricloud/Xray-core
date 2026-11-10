package tcp

import (
	"context"
	gotls "crypto/tls"
	stderrors "errors"
	"net"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common"
	xerrors "github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// Listener is an internet.Listener that listens for TCP connections.
type Listener struct {
	listener      xnet.Listener
	tlsConfig     *gotls.Config
	realityConfig *goreality.Config
	authConfig    internet.ConnectionAuthenticator
	config        *Config
	addConn       internet.ConnHandler
}

// ListenTCP creates a new Listener based on configurations.
func ListenTCP(ctx context.Context, address xnet.Address, port xnet.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	l := &Listener{
		addConn: handler,
	}
	tcpSettings := streamSettings.ProtocolSettings.(*Config)
	l.config = tcpSettings
	if l.config != nil {
		if streamSettings.SocketSettings == nil {
			streamSettings.SocketSettings = &internet.SocketConfig{}
		}
		streamSettings.SocketSettings.AcceptProxyProtocol = l.config.AcceptProxyProtocol || streamSettings.SocketSettings.AcceptProxyProtocol
	}
	var listener xnet.Listener
	var err error
	var addr xnet.Addr
	if port == xnet.Port(0) { // unix
		addr = &xnet.UnixAddr{Name: address.Domain(), Net: "unix"}
	} else { // tcp
		addr = &xnet.TCPAddr{IP: address.IP(), Port: int(port)}
	}
	if streamSettings.FinalMask != nil {
		listener, err = streamSettings.FinalMask.Listen(ctx, addr)
	} else {
		listener, err = internet.ListenSystem(ctx, addr, streamSettings.SocketSettings)
	}
	if err != nil {
		return nil, xerrors.New("failed to listen ", addr.Network(), " on ", address, ":", port).Base(err)
	}
	xerrors.LogInfo(ctx, "listening ", addr.Network(), " on ", address, ":", port)

	if streamSettings.SocketSettings != nil && streamSettings.SocketSettings.AcceptProxyProtocol {
		xerrors.LogWarning(ctx, "accepting PROXY protocol")
	}

	l.listener = listener

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		l.tlsConfig = config.GetTLSConfig()
	}
	if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
		l.realityConfig = config.GetREALITYConfig()
		go goreality.DetectPostHandshakeRecordsLens(l.realityConfig)
	}

	if tcpSettings.HeaderSettings != nil {
		headerConfig, err := tcpSettings.HeaderSettings.GetInstance()
		if err != nil {
			return nil, xerrors.New("invalid header settings").Base(err)
		}
		auth, err := internet.CreateConnectionAuthenticator(headerConfig)
		if err != nil {
			return nil, xerrors.New("invalid header settings.").Base(err)
		}
		l.authConfig = auth
	}

	go l.keepAccepting()
	return l, nil
}

func (v *Listener) keepAccepting() {
	for {
		conn, err := v.listener.Accept()
		if err != nil {
			if stderrors.Is(err, net.ErrClosed) {
				break
			}
			xerrors.LogWarningInner(context.Background(), err, "failed to accepted raw connections")
			time.Sleep(time.Millisecond * 100)
			continue
		}

		go func() {
			if v.tlsConfig != nil {
				conn = tls.Server(conn, v.tlsConfig)
			} else if v.realityConfig != nil {
				if conn, err = reality.Server(conn, v.realityConfig); err != nil {
					xerrors.LogInfo(context.Background(), err.Error())
					return
				}
			}
			if v.authConfig != nil {
				conn = v.authConfig.Server(conn)
			}
			v.addConn(stat.Connection(conn))
		}()
	}
}

// Addr implements internet.Listener.Addr.
func (v *Listener) Addr() net.Addr {
	return v.listener.Addr()
}

// Close implements internet.Listener.Close.
func (v *Listener) Close() error {
	return v.listener.Close()
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenTCP))
}
