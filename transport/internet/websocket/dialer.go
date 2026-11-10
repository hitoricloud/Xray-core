package websocket

import (
	"context"
	_ "embed"
	"encoding/base64"
	"io"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/browser_dialer"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// Dial dials a WebSocket connection to the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "creating connection to ", dest)
	var conn net.Conn
	if streamSettings.ProtocolSettings.(*Config).Ed > 0 {
		ctx, cancel := context.WithCancel(ctx)
		conn = &delayDialConn{
			dialed:         make(chan bool, 1),
			cancel:         cancel,
			ctx:            ctx,
			dest:           dest,
			streamSettings: streamSettings,
		}
	} else {
		var err error
		if conn, err = dialWebSocket(ctx, dest, streamSettings, nil); err != nil {
			return nil, errors.New("failed to dial WebSocket").Base(err)
		}
	}
	return stat.Connection(conn), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

func dialWebSocket(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig, ed []byte) (net.Conn, error) {
	wsSettings := streamSettings.ProtocolSettings.(*Config)

	dialer := &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			var conn net.Conn
			var err error
			if streamSettings.FinalMask != nil {
				conn, err = streamSettings.FinalMask.DialTCP(ctx, dest)
			} else {
				conn, err = internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
			}
			if err != nil {
				return nil, errors.New("failed to dial to dest").Base(err)
			}
			return conn, err
		},
		ReadBufferSize:   4 * 1024,
		WriteBufferSize:  0,
		WriteBufferPool:  wsBufferPool,
		HandshakeTimeout: time.Second * 8,
	}

	protocol := "ws"

	tConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tConfig != nil {
		protocol = "wss"
		tlsConfig := tConfig.GetTLSConfig(tls.WithDestination(dest), tls.WithNextProto("http/1.1"))
		dialer.TLSClientConfig = tlsConfig
		if fingerprint := tls.GetFingerprint(tConfig.Fingerprint); fingerprint != nil {
			dialer.NetDialTLSContext = func(_ context.Context, _, addr string) (net.Conn, error) {
				// Like the NetDial in the dialer
				var pconn net.Conn
				var err error
				if streamSettings.FinalMask != nil {
					pconn, err = streamSettings.FinalMask.DialTCP(ctx, dest)
				} else {
					pconn, err = internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
				}
				if err != nil {
					return nil, errors.New("failed to dial to dest").Base(err)
				}

				// TLS and apply the handshake
				cn := tls.UClient(pconn, tlsConfig, fingerprint).(*tls.UConn)
				if err := cn.WebsocketHandshakeContext(ctx); err != nil {
					errors.LogErrorInner(ctx, err, "failed to dial to "+addr)
					return nil, err
				}
				if !tlsConfig.InsecureSkipVerify {
					if err := cn.VerifyHostname(tlsConfig.ServerName); err != nil {
						errors.LogErrorInner(ctx, err, "failed to dial to "+addr)
						return nil, err
					}
				}
				return cn, nil
			}
		}
	}

	if browser_dialer.HasBrowserDialer() {
		// For Browser Dialer's optimized IP and non-standard port
		host := wsSettings.Host
		if host == "" && tConfig.ServerName != "" {
			host = tConfig.ServerName
		}
		if host == "" {
			host = dest.Address.String()
		}
		if !(protocol == "ws" && dest.Port == 80) && !(protocol == "wss" && dest.Port == 443) {
			host += ":" + dest.Port.String()
		}
		uri := protocol + "://" + host + wsSettings.GetNormalizedPath()

		conn, err := browser_dialer.DialWS(uri, ed)
		if err != nil {
			return nil, err
		}

		return NewConnection(conn, conn.RemoteAddr(), nil, wsSettings.HeartbeatPeriod), nil
	}

	host := dest.Address.String()
	if !(protocol == "ws" && dest.Port == 80) && !(protocol == "wss" && dest.Port == 443) {
		host += ":" + dest.Port.String()
	}
	uri := protocol + "://" + host + wsSettings.GetNormalizedPath()

	header := wsSettings.GetRequestHeader()
	// See dialer.DialContext()
	header.Set("Host", wsSettings.Host)
	if header.Get("Host") == "" && tConfig != nil {
		header.Set("Host", tConfig.ServerName)
	}
	if header.Get("Host") == "" {
		header.Set("Host", dest.Address.String())
	}
	if ed != nil {
		// RawURLEncoding is support by both V2Ray/V2Fly and XRay.
		header.Set("Sec-WebSocket-Protocol", base64.RawURLEncoding.EncodeToString(ed))
	}

	conn, resp, err := dialer.DialContext(ctx, uri, header)
	if err != nil {
		var reason string
		if resp != nil {
			reason = resp.Status
		}
		return nil, errors.New("failed to dial to (", uri, "): ", reason).Base(err)
	}

	return NewConnection(conn, conn.RemoteAddr(), nil, wsSettings.HeartbeatPeriod), nil
}

type delayDialConn struct {
	net.Conn
	mu             sync.RWMutex
	writeMu        sync.Mutex
	closed         bool
	dialed         chan bool
	cancel         context.CancelFunc
	ctx            context.Context
	dest           net.Destination
	streamSettings *internet.MemoryStreamConfig
}

func (d *delayDialConn) connectionState() (net.Conn, bool) {
	d.mu.RLock()
	conn, closed := d.Conn, d.closed
	d.mu.RUnlock()
	return conn, closed
}

// LocalAddr is unavailable until the deferred dial completes.
func (d *delayDialConn) LocalAddr() net.Addr {
	conn, _ := d.connectionState()
	if conn == nil {
		return nil
	}
	return conn.LocalAddr()
}

// RemoteAddr is unavailable until the deferred dial completes.
func (d *delayDialConn) RemoteAddr() net.Addr {
	conn, _ := d.connectionState()
	if conn == nil {
		return nil
	}
	return conn.RemoteAddr()
}

func (d *delayDialConn) SetDeadline(t time.Time) error {
	conn, closed := d.connectionState()
	if conn == nil || closed {
		return io.ErrClosedPipe
	}
	return conn.SetDeadline(t)
}

func (d *delayDialConn) SetReadDeadline(t time.Time) error {
	conn, closed := d.connectionState()
	if conn == nil || closed {
		return io.ErrClosedPipe
	}
	return conn.SetReadDeadline(t)
}

func (d *delayDialConn) SetWriteDeadline(t time.Time) error {
	conn, closed := d.connectionState()
	if conn == nil || closed {
		return io.ErrClosedPipe
	}
	return conn.SetWriteDeadline(t)
}

func (d *delayDialConn) Write(b []byte) (int, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	conn, closed := d.connectionState()
	if closed {
		return 0, io.ErrClosedPipe
	}
	if conn == nil {
		ed := b
		if len(ed) > int(d.streamSettings.ProtocolSettings.(*Config).Ed) {
			ed = nil
		}
		var err error
		if conn, err = dialWebSocket(d.ctx, d.dest, d.streamSettings, ed); err != nil {
			d.Close()
			return 0, errors.New("failed to dial WebSocket").Base(err)
		}
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			conn.Close()
			return 0, io.ErrClosedPipe
		}
		d.Conn = conn
		d.mu.Unlock()
		close(d.dialed)
		if ed != nil {
			return len(ed), nil
		}
	}
	return conn.Write(b)
}

func (d *delayDialConn) Read(b []byte) (int, error) {
	conn, closed := d.connectionState()
	if closed {
		return 0, io.ErrClosedPipe
	}
	if conn == nil {
		select {
		case <-d.ctx.Done():
			return 0, io.ErrUnexpectedEOF
		case <-d.dialed:
		}
		conn, closed = d.connectionState()
		if closed {
			return 0, io.ErrClosedPipe
		}
	}
	return conn.Read(b)
}

func (d *delayDialConn) Close() error {
	d.mu.Lock()
	d.closed = true
	conn := d.Conn
	d.mu.Unlock()
	if d.cancel != nil {
		d.cancel()
	}
	if conn == nil {
		return nil
	}
	return conn.Close()
}
