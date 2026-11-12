package hmc

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

const testPassword = "test-only-password-32-bytes-minimum"

func TestSessionKeys(t *testing.T) {
	token, secret := []byte{1, 2, 3, 4}, bytes.Repeat([]byte{5}, fieldLength)
	base, err := deriveSessionKeys(testPassword, token, secret)
	if err != nil {
		t.Fatal(err)
	}
	again, err := deriveSessionKeys(testPassword, token, secret)
	if err != nil || *base != *again {
		t.Fatalf("nondeterministic keys: %v", err)
	}
	if base.clientToServer == base.serverToClient {
		t.Fatal("directions share keys")
	}
	for _, tc := range []struct {
		password      string
		token, secret []byte
	}{
		{testPassword + "x", token, secret},
		{testPassword, []byte{9, 2, 3, 4}, secret},
		{testPassword, token, bytes.Repeat([]byte{6}, fieldLength)},
	} {
		other, err := deriveSessionKeys(tc.password, tc.token, tc.secret)
		if err != nil || base.clientToServer == other.clientToServer || base.serverToClient == other.serverToClient {
			t.Fatalf("unchanged derived direction: %v", err)
		}
	}
}

func TestLoginResponseShape(t *testing.T) {
	key, token := testPublicKey(t), []byte{1, 2, 3, 4}
	secret, proof, keys, err := newLoginResponse(testPassword, key, token)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 128 || len(proof) != 128 || secret[0]&0x80 != 0 || proof[0]&0x80 != 0 {
		t.Fatal("invalid field shape")
	}
	mac := hmac.New(sha256.New, passwordSecret(testPassword))
	for _, part := range [][]byte{[]byte("hmc1 proof"), key, token, secret} {
		mac.Write(part)
	}
	if !hmac.Equal(proof[96:], mac.Sum(nil)) {
		t.Fatal("proof not in final 32 bytes")
	}
	verified, err := verifyLoginResponse(testPassword, key, token, secret, proof)
	if err != nil || *keys != *verified {
		t.Fatalf("verification: %v", err)
	}
}

func previousLoginResponse(t *testing.T, profile loginProfile, publicKey []byte) ([]byte, []byte, []byte) {
	t.Helper()
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	server, err := testServerConn(peer, []loginProfile{profile}, testPassword, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.handshake() }()
	version, host, port, state := Varint(775), loginKnock(testPassword, "localhost", String(profile.Username), profile.UUID, time.Now().Unix()/30), UnsignedShort(25565), Varint(2)
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
	var id String
	var key, token Bytes
	var auth Boolean
	if err := request.readFields(&id, &key, &token, &auth); err != nil {
		t.Fatal(err)
	}
	binding := loginBinding(version, host, port, username, profile.UUID, id, key, token)
	secret, proof, _, err := newLoginResponse(testPassword, binding, token, key)
	if err != nil {
		t.Fatal(err)
	}
	s, p := Bytes(secret), Bytes(proof)
	if err := writePacket(raw, 1, &s, &p); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	<-done
	return secret, proof, token
}

func TestUnauthenticatedFailuresAreSilent(t *testing.T) {
	profile, publicKey := testLoginProfile("test_user"), testPublicKey(t)
	for _, name := range []string{"wrong password", "wrong token", "different public key", "spliced secret", "short secret", "long secret", "empty secret", "short proof", "long proof", "empty proof", "replay", "garbage"} {
		t.Run(name, func(t *testing.T) {
			var oldSecret, oldProof, oldToken []byte
			if name == "replay" {
				oldSecret, oldProof, oldToken = previousLoginResponse(t, profile, publicKey)
			}
			raw, serverRaw := net.Pipe()
			defer raw.Close()
			defer serverRaw.Close()
			for _, c := range []net.Conn{raw, serverRaw} {
				if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			server, err := testServerConn(serverRaw, []loginProfile{profile}, testPassword, publicKey)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				first := server.handshake()
				if !errors.Is(first, errInvalidLogin) {
					done <- fmt.Errorf("auth: %v", first)
					return
				}
				if server.handshake() != first {
					done <- errors.New("non-sticky error")
					return
				}
				done <- nil
			}()
			var start bytes.Buffer
			version, host, port, state := Varint(775), loginKnock(testPassword, "localhost", String(profile.Username), profile.UUID, time.Now().Unix()/30), UnsignedShort(25565), Varint(2)
			username := String(profile.Username)
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
			var key, token Bytes
			var authenticate Boolean
			if err := request.readFields(&serverID, &key, &token, &authenticate); err != nil {
				t.Fatal(err)
			}
			proofPassword := testPassword
			proofKey, proofToken := []byte(key), append([]byte(nil), token...)
			switch name {
			case "wrong password":
				proofPassword = strings.Repeat("x", len(testPassword))
			case "wrong token":
				proofToken[0] ^= 1
			case "different public key":
				proofKey = append([]byte(nil), key...)
				proofKey[0] ^= 1
			}
			binding := loginBinding(version, host, port, username, profile.UUID, serverID, proofKey, proofToken)
			secret, proof, _, err := newLoginResponse(proofPassword, binding, proofToken, key)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "replay":
				if bytes.Equal(oldToken, token) {
					t.Skip("random tokens collided")
				}
				secret, proof = oldSecret, oldProof
			case "spliced secret":
				secret[1] ^= 1
			case "short secret":
				secret = secret[:127]
			case "long secret":
				secret = append(secret, 0)
			case "empty secret":
				secret = nil
			case "short proof":
				proof = proof[:127]
			case "long proof":
				proof = append(proof, 0)
			case "empty proof":
				proof = nil
			case "garbage":
				secret, proof = make([]byte, 128), make([]byte, 128)
			}
			s, p := Bytes(secret), Bytes(proof)
			if err := writePacket(raw, 1, &s, &p); err != nil {
				t.Fatal(err)
			}
			wire, err := io.ReadAll(raw)
			if err != nil || len(wire) != 0 {
				t.Fatalf("expected silent close: %d bytes, %v", len(wire), err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLoginProofRejectsSplicedSecret(t *testing.T) {
	profile, publicKey := testLoginProfile("test_user"), testPublicKey(t)
	toServer, serverRaw := net.Pipe()
	fromClient, clientRaw := net.Pipe()
	for _, c := range []net.Conn{toServer, serverRaw, fromClient, clientRaw} {
		defer c.Close()
		if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	server, err := testServerConn(serverRaw, []loginProfile{profile}, testPassword, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	client, err := newClientConn(clientRaw, []loginProfile{profile}, testPassword, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	serverDone, clientDone := make(chan error, 1), make(chan error, 1)
	go func() { serverDone <- server.handshake() }()
	go func() { clientDone <- client.handshake() }()
	relay := func(dst, src net.Conn) {
		t.Helper()
		p, err := readPacket(src)
		if err != nil {
			t.Fatal(err)
		}
		body := RestBytes(p.data)
		if err := writePacket(dst, p.packetID, &body); err != nil {
			t.Fatal(err)
		}
	}
	relay(toServer, fromClient)
	relay(toServer, fromClient)
	relay(fromClient, toServer)
	response, err := readPacket(fromClient)
	if err != nil {
		t.Fatal(err)
	}
	var victimSecret, proof Bytes
	if err := response.readFields(&victimSecret, &proof); err != nil {
		t.Fatal(err)
	}
	chosen, err := randomField()
	if err != nil {
		t.Fatal(err)
	}
	chosen[1] = victimSecret[1] ^ 1
	attacker := Bytes(chosen)
	if err := writePacket(toServer, 1, &attacker, &proof); err != nil {
		t.Fatal(err)
	}
	wire, err := io.ReadAll(toServer)
	if err != nil || len(wire) != 0 {
		t.Fatalf("spliced response: %d bytes, %v", len(wire), err)
	}
	if err := <-serverDone; !errors.Is(err, errInvalidLogin) {
		t.Fatalf("server: %v", err)
	}
	fromClient.Close()
	if err := <-clientDone; err == nil {
		t.Fatal("client unexpectedly succeeded")
	}
}

func TestClientHandshakeFailureIsSticky(t *testing.T) {
	raw, remote := net.Pipe()
	defer raw.Close()
	remote.Close()
	client, err := newClientConn(raw, []loginProfile{testLoginProfile("test_user")}, testPassword, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	first := client.handshake()
	if first == nil || client.handshake() != first {
		t.Fatalf("non-sticky failure: %v", first)
	}
}
