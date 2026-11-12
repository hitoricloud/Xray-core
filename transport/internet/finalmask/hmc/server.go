package hmc

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Response by vanilla 26.1.2 server.
var statusResponse = `{"description":"A Minecraft Server","players":{"max":20,"online":0},"version":{"name":"26.1.2","protocol":775},"enforcesSecureChat":true}`

var errAdmissionRejected = errors.New("HMC admission rejected")

var fillVerifyToken = func(token []byte) error {
	_, err := rand.Read(token)
	return err
}

type serverState int

var (
	serverStateHandshake serverState = 1
	serverStateProxy     serverState = 3
)

type serverConn struct {
	reader io.Reader
	writer io.Writer
	c      net.Conn

	state serverState

	handshakeLock   sync.Mutex
	handshakeErr    error
	lifecycleMu     sync.Mutex
	closed          bool
	password        string
	publicKey       []byte
	packet          *packetStream
	deadlines       *connectionDeadlines
	dest            string
	protocolVersion uint32
	recording       *recordingReader
	relayLimits     *relayLimits
	knocks          *replayCache
	now             func() time.Time
	limiter         *admissionLimiter
	admission       *admissionLease
	knockSlot       *knockSlot
}

func (c *serverConn) handshake() (err error) {
	c.handshakeLock.Lock()
	defer c.handshakeLock.Unlock()

	if c.handshakeErr != nil {
		return c.handshakeErr
	}
	if c.state != serverStateHandshake {
		return nil
	}
	if c.limiter != nil {
		lease := c.limiter.acquire(admissionIP(c.c.RemoteAddr()), c.c)
		if lease == nil {
			c.handshakeErr = errAdmissionRejected
			_ = c.c.Close()
			return c.handshakeErr
		}
		c.lifecycleMu.Lock()
		if c.closed {
			c.lifecycleMu.Unlock()
			lease.release()
			c.handshakeErr = net.ErrClosed
			return c.handshakeErr
		}
		c.admission = lease
		c.lifecycleMu.Unlock()
	}
	defer c.admission.release()
	defer func() {
		if err != nil {
			c.handshakeErr = err
			_ = c.c.Close()
		}
	}()

	if err := c.deadlines.beginHandshake(); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	recognizedKnock := false
	defer func() {
		_ = c.deadlines.endHandshake()
		c.admission.release()
		if err != nil && !recognizedKnock && c.dest != "" {
			limits := fallbackLimits
			if c.relayLimits != nil {
				limits = *c.relayLimits
			}
			c.admission.relay(c.c, c.dest, c.recording.Bytes(), limits)
		}
	}()

	var (
		protocolVersion Varint
		serverAddress   String
		serverPort      UnsignedShort
		nextState       Varint
	)

	if c.dest != "" {
		reader := bufio.NewReader(c.reader)
		c.reader = reader
		first, peekErr := reader.Peek(1)
		if peekErr != nil {
			return fmt.Errorf("peek handshake: %w", peekErr)
		}
		if first[0] == 0xfe {
			return fmt.Errorf("relay legacy ping")
		}
	}

	pkt, err := readPreAuthPacket(c.reader)
	if err != nil {
		return fmt.Errorf("read handshake packet: %w", err)
	}
	if pkt.packetID != 0 {
		return fmt.Errorf("bad handshake packet id")
	}
	if err = pkt.readFields(&protocolVersion, &serverAddress, &serverPort, &nextState); err != nil {
		return fmt.Errorf("read handshake packet: %w", err)
	}

	switch nextState {
	case 1:
		if c.dest != "" {
			return fmt.Errorf("relay status")
		}
		for range 2 {
			pkt, err := readPreAuthPacket(c.reader)
			if err != nil {
				return fmt.Errorf("read packet: %w", err)
			}

			switch pkt.packetID {
			case 0: // Status Request
				if err = writePacket(c.writer, 0, new(String(statusResponse))); err != nil {
					return fmt.Errorf("write status response: %w", err)
				}
			case 1: // Ping
				var payload Long
				if err = pkt.readFields(&payload); err != nil {
					return fmt.Errorf("read ping packet: %w", err)
				}
				if err = writePacket(c.writer, 1, &payload); err != nil {
					return fmt.Errorf("write ping response: %w", err)
				}
			}
		}
		return fmt.Errorf("ping")

	case 2:
		pkt, err := readPreAuthPacket(c.reader)
		if err != nil {
			return fmt.Errorf("read login start packet: %w", err)
		}
		if pkt.packetID != 0 {
			return fmt.Errorf("bad login start packet id")
		}

		var (
			username String
			uuid     UUID
		)
		if err = pkt.readFields(&username, &uuid); err != nil {
			return fmt.Errorf("read login start packet: %w", err)
		}
		now := c.now()
		if !validKnock(c.password, serverAddress, username, uuid, now) {
			return errInvalidLogin
		}
		// A knock that already completed a login is relayed like any outsider, as a real server would answer.
		if c.knocks.contains(knockToken(serverAddress), now) {
			return errInvalidLogin
		}
		slot := acquireKnockSlot(knockToken(serverAddress))
		if slot == nil {
			return errInvalidLogin
		}
		recognizedKnock = true
		defer slot.release()
		c.lifecycleMu.Lock()
		if c.closed {
			c.lifecycleMu.Unlock()
			return net.ErrClosed
		}
		c.knockSlot = slot
		c.lifecycleMu.Unlock()
		if !c.admission.postKnock(slot) {
			return errInvalidLogin
		}
		c.recording.active = false
		c.recording.Reset()
		publishedKey, publishedID := c.publicKey, String("")
		if c.dest != "" {
			if key, id := cachedDest(c.dest, c.protocolVersion); len(key) > 0 {
				publishedKey, publishedID = key, id
			}
		}

		var (
			serverId           String  = publishedID
			publicKey          Bytes   = Bytes(publishedKey)
			verifyToken        Bytes   = Bytes(make([]byte, tokenLength))
			shouldAuthenticate Boolean = true
		)
		if err = fillVerifyToken(verifyToken); err != nil {
			return fmt.Errorf("generate verify token: %w", err)
		}
		if err = writePacket(c.writer, 0x01, &serverId, &publicKey, &verifyToken, &shouldAuthenticate); err != nil {
			return fmt.Errorf("write encryption request: %w", err)
		}

		pkt, err = readPacket(c.reader)
		if err != nil {
			return fmt.Errorf("read encrypt response: %w", err)
		}
		if pkt.packetID != 0x01 {
			return fmt.Errorf("bad encrypt response packet id")
		}

		var secretField, proofField Bytes
		if err = pkt.readFields(&secretField, &proofField); err != nil {
			return fmt.Errorf("read encrypt response: %w", err)
		}

		binding := loginBinding(protocolVersion, serverAddress, serverPort, username, uuid, serverId, publicKey, verifyToken)
		keys, err := verifyLoginResponse(c.password, binding, verifyToken, secretField, proofField, publicKey)
		if err != nil {
			return err
		}
		if !c.admission.proofVerified() {
			return errInvalidLogin
		}
		if !c.knocks.firstUse(knockToken(serverAddress), c.now()) {
			return errInvalidLogin
		}
		if !loginReplays.firstUse(secretField, time.Now()) {
			return errInvalidLogin
		}
		if c.reader, err = newBufferedCryptoReader(c.reader, keys.clientToServer); err != nil {
			return fmt.Errorf("new crypto reader: %w", err)
		}
		if c.writer, err = newCryptoWriter(c.writer, keys.serverToClient); err != nil {
			return fmt.Errorf("new crypto writer: %w", err)
		}

		propertyCount := Varint(0)
		if err = writePacket(c.writer, 0x02, &uuid, &username, &propertyCount); err != nil {
			return fmt.Errorf("write login finished: %w", err)
		}

		pkt, err = readPacket(c.reader)
		if err != nil {
			return fmt.Errorf("read login acknowledged: %w", err)
		}
		if err = validateLoginAcknowledgedPacket(pkt); err != nil {
			return err
		}

		packet := newPacketStream(c.reader, c.writer, false)
		c.lifecycleMu.Lock()
		if c.closed {
			c.lifecycleMu.Unlock()
			packet.Stop()
			return net.ErrClosed
		}
		c.admission.credit()
		c.packet = packet
		c.reader = packet
		c.writer = packet
		c.state = serverStateProxy
		c.lifecycleMu.Unlock()

		return nil

	default:
		return fmt.Errorf("bad handshake packet: bad next state: %d", nextState)
	}
}

func validateLoginAcknowledgedPacket(pkt *mcPacket) error {
	if pkt.packetID != 0x03 {
		return fmt.Errorf("bad login acknowledged packet id: %d", pkt.packetID)
	}
	if len(pkt.data) != 0 {
		return fmt.Errorf("bad login acknowledged packet data length: %d", len(pkt.data))
	}
	return nil
}

func (c *serverConn) Read(b []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, fmt.Errorf("handshake: %w", err)
	}
	return c.reader.Read(b)
}

func (c *serverConn) Write(b []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, fmt.Errorf("handshake: %w", err)
	}
	return c.writer.Write(b)
}

func (c *serverConn) Close() error {
	c.lifecycleMu.Lock()
	lease := c.admission
	slot := c.knockSlot
	c.closed = true
	packet := c.packet
	c.lifecycleMu.Unlock()
	lease.release()
	slot.release()
	if packet != nil {
		packet.Stop()
	}
	return c.c.Close()
}

func (c *serverConn) LocalAddr() net.Addr  { return c.c.LocalAddr() }
func (c *serverConn) RemoteAddr() net.Addr { return c.c.RemoteAddr() }

func (c *serverConn) SetDeadline(t time.Time) error      { return c.deadlines.setDeadline(t) }
func (c *serverConn) SetReadDeadline(t time.Time) error  { return c.deadlines.setReadDeadline(t) }
func (c *serverConn) SetWriteDeadline(t time.Time) error { return c.deadlines.setWriteDeadline(t) }

func wrapConnServer(c net.Conn, _ []loginProfile, password string, publicKey []byte) (*serverConn, error) {
	if len(publicKey) == 0 {
		return nil, fmt.Errorf("empty camouflage public key")
	}

	recording := &recordingReader{conn: c, active: true}
	return &serverConn{
		recording: recording,
		knocks:    knockReplays,
		now:       time.Now,
		reader:    bufio.NewReader(recording),
		writer:    c,
		c:         c,
		state:     serverStateHandshake,
		password:  password,
		publicKey: publicKey,
		deadlines: newConnectionDeadlines(c),
	}, nil
}
