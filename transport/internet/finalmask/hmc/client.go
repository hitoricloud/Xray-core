package hmc

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type clientConn struct {
	reader io.Reader
	writer io.Writer
	c      net.Conn

	state clientState

	handshakeLock   sync.Mutex
	handshakeErr    error
	lifecycleMu     sync.Mutex
	closed          bool
	releaseProfile  func()
	password        string
	hostname        string
	packet          *packetStream
	deadlines       *connectionDeadlines
	protocolVersion uint32
	loginMu         sync.Mutex
	loginReader     io.Reader
	selectedProfile loginProfile
	loginValidated  bool
}

type clientState int

var (
	clientStateHandshake clientState = 1
	clientStateProxy     clientState = 2
)

func newClientConn(c net.Conn, profiles []loginProfile, password string, hostname string) (*clientConn, error) {
	if len(profiles) == 0 {
		return nil, fmt.Errorf("empty profiles")
	}
	profile, release, err := poolFor(password, profiles).lease()
	if err != nil {
		return nil, fmt.Errorf("lease profile: %w", err)
	}
	return &clientConn{
		selectedProfile: profile,
		releaseProfile:  release,
		reader:          bufio.NewReader(c),
		writer:          c,
		c:               c,
		state:           clientStateHandshake,
		password:        password,
		hostname:        hostname,
		deadlines:       newConnectionDeadlines(c),
	}, nil
}

func (c *clientConn) handshake() (err error) {
	c.handshakeLock.Lock()
	defer c.handshakeLock.Unlock()

	if c.handshakeErr != nil {
		return c.handshakeErr
	}
	if c.state != clientStateHandshake {
		return nil
	}
	defer func() {
		if err != nil {
			c.handshakeErr = err
			_ = c.Close()
		}
	}()

	if err := c.deadlines.beginHandshake(); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	defer func() { _ = c.deadlines.endHandshake() }()

	var (
		protocolVersion Varint        = effectiveVersion(c.protocolVersion)
		serverAddress   String        = String(c.hostname)
		serverPort      UnsignedShort = UnsignedShort(25565)
		nextState       Varint        = Varint(2)
	)

	host, portString, err := net.SplitHostPort(c.c.RemoteAddr().String())
	if err == nil {
		if port, err := strconv.Atoi(portString); err == nil {
			serverPort = UnsignedShort(port)
		}
		if serverAddress == "" {
			serverAddress = String(host)
		}
	}

	selectedProfile := c.selectedProfile
	username := String(selectedProfile.Username)
	serverAddress = loginKnock(c.password, serverAddress, username, selectedProfile.UUID, time.Now().Unix()/30)
	if err = writePacket(c.writer, 0x00, &protocolVersion, &serverAddress, &serverPort, &nextState); err != nil {
		return fmt.Errorf("write handshake packet: %w", err)
	}

	if err = writePacket(c.writer, 0x00, &username, &selectedProfile.UUID); err != nil {
		return fmt.Errorf("write login start: %w", err)
	}

	pkt, err := readPacket(c.reader)
	if err != nil {
		return fmt.Errorf("read encryption request: %w", err)
	}
	if pkt.packetID != 0x01 {
		return fmt.Errorf("bad encrypt request packet id")
	}

	var (
		serverId    String
		publicKey   Bytes
		verifyToken Bytes
	)
	if err = pkt.readFields(&serverId, &publicKey, &verifyToken); err != nil {
		return fmt.Errorf("read encryption request fields: %w", err)
	}

	binding := loginBinding(protocolVersion, serverAddress, serverPort, username, selectedProfile.UUID, serverId, publicKey, verifyToken)
	secretField, proofField, keys, err := newLoginResponse(c.password, binding, verifyToken, publicKey)
	if err != nil {
		return fmt.Errorf("build encryption response: %w", err)
	}
	var response bytes.Buffer
	if err = writePacket(&response, 0x01, (*Bytes)(&secretField), (*Bytes)(&proofField)); err != nil {
		return fmt.Errorf("write encryption response: %w", err)
	}

	if c.reader, err = newBufferedCryptoReader(c.reader, keys.serverToClient); err != nil {
		return fmt.Errorf("new crypto reader: %w", err)
	}
	encryptedWriter, err := newCryptoWriter(&response, keys.clientToServer)
	if err != nil {
		return fmt.Errorf("new crypto writer: %w", err)
	}
	c.loginReader = c.reader
	if err = writePacket(encryptedWriter, 0x03); err != nil {
		return fmt.Errorf("write login acknowledged: %w", err)
	}
	if err = writeFull(c.writer, response.Bytes()); err != nil {
		return fmt.Errorf("write pipelined login: %w", err)
	}
	encryptedWriter.w = c.writer
	c.writer = encryptedWriter

	packet := newPacketStream(c.reader, c.writer, true)
	c.lifecycleMu.Lock()
	if c.closed {
		c.lifecycleMu.Unlock()
		packet.Stop()
		return net.ErrClosed
	}
	c.packet = packet
	c.reader = packet
	c.writer = packet
	c.state = clientStateProxy
	c.lifecycleMu.Unlock()

	return nil
}

func (c *clientConn) validateLogin() (err error) {
	c.loginMu.Lock()
	defer c.loginMu.Unlock()
	c.handshakeLock.Lock()
	previous := c.handshakeErr
	c.handshakeLock.Unlock()
	if previous != nil {
		return previous
	}
	if c.loginValidated {
		return nil
	}
	transient := false
	defer func() {
		if err != nil && !transient {
			c.handshakeLock.Lock()
			c.handshakeErr = err
			c.handshakeLock.Unlock()
			_ = c.Close()
		}
	}()
	if err = c.deadlines.beginHandshake(); err != nil {
		return err
	}
	defer func() { _ = c.deadlines.endHandshake() }()
	frame := &countingReader{r: c.loginReader}
	pkt, err := readPacket(frame)
	if err != nil {
		var timeout net.Error
		transient = frame.n == 0 && errors.As(err, &timeout) && timeout.Timeout()
		return streamError("read login finished", err)
	}
	if pkt.packetID == 0 {
		return fmt.Errorf("authentication rejected")
	}
	if pkt.packetID != 2 {
		return fmt.Errorf("bad login finished packet id: %d", pkt.packetID)
	}
	received, err := readLoginSuccess(pkt)
	if err != nil {
		return fmt.Errorf("read login finished fields: %w", err)
	}
	if received != c.selectedProfile {
		return fmt.Errorf("login profile mismatch")
	}
	c.loginValidated = true
	return nil
}

func (c *clientConn) Read(b []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, fmt.Errorf("handshake: %w", err)
	}
	if err := c.validateLogin(); err != nil {
		return 0, fmt.Errorf("handshake: %w", err)
	}
	return c.reader.Read(b)
}

func (c *clientConn) Write(b []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, fmt.Errorf("handshake: %w", err)
	}
	return c.writer.Write(b)
}

func (c *clientConn) Close() error {
	c.lifecycleMu.Lock()
	c.closed = true
	packet := c.packet
	c.lifecycleMu.Unlock()
	if packet != nil {
		packet.Stop()
	}
	err := c.c.Close()
	c.releaseProfile()
	return err
}

func (c *clientConn) LocalAddr() net.Addr  { return c.c.LocalAddr() }
func (c *clientConn) RemoteAddr() net.Addr { return c.c.RemoteAddr() }

func (c *clientConn) SetDeadline(t time.Time) error      { return c.deadlines.setDeadline(t) }
func (c *clientConn) SetReadDeadline(t time.Time) error  { return c.deadlines.setReadDeadline(t) }
func (c *clientConn) SetWriteDeadline(t time.Time) error { return c.deadlines.setWriteDeadline(t) }
