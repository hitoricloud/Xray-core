package hmc

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type blockedWriter struct{ release chan struct{} }

func (w blockedWriter) Write(p []byte) (int, error) {
	<-w.release
	return len(p), nil
}

// A keep-alive reply blocked by peer backpressure must not stop Read.
func TestClientKeepAliveDoesNotBlockRead(t *testing.T) {
	var wire bytes.Buffer
	id := Long(7)
	channel, payload := String(packetChannel), RestBytes("data")
	if err := writePacket(&wire, configurationKeepAlive, &id); err != nil {
		t.Fatal(err)
	}
	if err := writePacket(&wire, configurationClientboundCustomPayload, &channel, &payload); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	stream := newPacketStream(bytes.NewReader(wire.Bytes()), blockedWriter{release}, true)
	t.Cleanup(func() { close(release); stream.Stop() })

	done := make(chan error, 1)
	go func() {
		got := make([]byte, 4)
		_, err := io.ReadFull(stream, got)
		if err == nil && string(got) != "data" {
			err = errors.New("unexpected payload")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client Read blocked behind a keep-alive write")
	}
}

func TestPreAuthPacketLimit(t *testing.T) {
	var prefix bytes.Buffer
	length := Varint(preAuthPacketBodyLength + 1)
	if err := length.writeTo(&prefix); err != nil {
		t.Fatal(err)
	}
	if _, err := readPreAuthPacket(&prefix); err == nil || !strings.Contains(err.Error(), "bad length") {
		t.Fatalf("oversized pre-auth frame must be rejected from its prefix, got %v", err)
	}
}

func TestPasswordSecretIsStretched(t *testing.T) {
	first, again := passwordSecret(testPassword), passwordSecret(testPassword)
	other := passwordSecret(testPassword + "x")
	if len(first) != 32 || !bytes.Equal(first, again) || bytes.Equal(first, other) || bytes.HasPrefix([]byte(testPassword), first) {
		t.Fatal("password secret must be a deterministic 32-byte stretch")
	}
}

type loginFixture struct {
	raw     net.Conn
	done    chan error
	token   []byte
	profile loginProfile
	key     []byte
	address String
}

func startLoginFixture(t *testing.T, token []byte, addresses ...String) *loginFixture {
	t.Helper()
	old := fillVerifyToken
	fillVerifyToken = func(b []byte) error { copy(b, token); return nil }
	t.Cleanup(func() { fillVerifyToken = old })

	profile, publicKey := testLoginProfile("test_user"), testPublicKey(t)
	raw, serverRaw := net.Pipe()
	t.Cleanup(func() { raw.Close(); serverRaw.Close() })
	for _, conn := range []net.Conn{raw, serverRaw} {
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	server, err := testServerConn(serverRaw, []loginProfile{profile}, testPassword, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return fallbackTime }
	done := make(chan error, 1)
	go func() { done <- server.handshake() }()

	host := loginKnock(testPassword, "localhost", "test_user", profile.UUID, fallbackTime.Unix()/30)
	if len(addresses) > 0 {
		host = addresses[0]
	}
	version, port, state := Varint(775), UnsignedShort(25565), Varint(2)
	username := String(profile.Username)
	var start bytes.Buffer
	if err := writePacket(&start, 0, &version, &host, &port, &state); err != nil {
		t.Fatal(err)
	}
	if err := writePacket(&start, 0, &username, &profile.UUID); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Write(start.Bytes()); err != nil {
		t.Fatal(err)
	}
	request, err := readPacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	var serverID String
	var gotKey, gotToken Bytes
	var authenticate Boolean
	if err := request.readFields(&serverID, &gotKey, &gotToken, &authenticate); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotToken, token) {
		t.Fatal("injected server token was not used")
	}
	return &loginFixture{raw: raw, done: done, token: token, profile: profile, key: publicKey, address: host}
}

func (f *loginFixture) binding(username string) []byte {
	return loginBinding(775, f.address, 25565, String(username), f.profile.UUID, "", f.key, f.token)
}

func (f *loginFixture) send(t *testing.T, secret, proof []byte) {
	t.Helper()
	s, p := Bytes(secret), Bytes(proof)
	if err := writePacket(f.raw, 1, &s, &p); err != nil {
		t.Fatal(err)
	}
}

func (f *loginFixture) expectSilentRejection(t *testing.T) {
	t.Helper()
	if reply, err := io.ReadAll(f.raw); err != nil || len(reply) != 0 {
		t.Fatalf("expected silent close, got %d bytes, %v", len(reply), err)
	}
	if err := <-f.done; err != errInvalidLogin {
		t.Fatalf("expected errInvalidLogin, got %v", err)
	}
}

// The server token is injected so the replayed proof reaches the replay cache,
// not the HMAC check that a changed token would fail first.
func TestReplayedResponseWithSameTokenIsRejected(t *testing.T) {
	oldCache := loginReplays
	loginReplays = newReplayCache(16, time.Hour)
	t.Cleanup(func() { loginReplays = oldCache })

	token := []byte{9, 8, 7, 6}
	first := startLoginFixture(t, token)
	secret, proof, keys, err := newLoginResponse(testPassword, first.binding(first.profile.Username), token)
	if err != nil {
		t.Fatal(err)
	}
	first.send(t, secret, proof)
	reader, err := newCryptoReader(first.raw, keys.serverToClient)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := readPacket(reader)
	if err != nil {
		t.Fatalf("genuine response was rejected: %v", err)
	}
	if _, err := readLoginSuccess(packet); err != nil {
		t.Fatal(err)
	}
	first.raw.Close()
	<-first.done

	second := startLoginFixture(t, token, first.address)
	second.send(t, secret, proof)
	second.expectSilentRejection(t)
}

// An on-path edit of plaintext Handshake/Login Start must invalidate the proof.
func TestTamperedHandshakeBindingIsRejected(t *testing.T) {
	f := startLoginFixture(t, []byte{1, 3, 5, 7})
	secret, proof, _, err := newLoginResponse(testPassword, f.binding("another_user"), f.token)
	if err != nil {
		t.Fatal(err)
	}
	f.send(t, secret, proof)
	f.expectSilentRejection(t)
}
