package hmc

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPipelinedEarlyWriteAndStickyLoginValidation(t *testing.T) {
	for _, mode := range []string{"success", "property", "unsigned", "uuid", "username", "properties", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			raw, peer := tcpPair(t)
			defer raw.Close()
			defer peer.Close()
			_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
			profile := testLoginProfile("test_user")
			client, err := newClientConn(raw, []loginProfile{profile}, testPassword, "localhost")
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.protocolVersion = 776
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			early := make(chan struct{})
			release := make(chan struct{})
			serverDone := make(chan error, 1)
			key := testPublicKey(t)
			go func() { serverDone <- servePipeline(peer, profile, key, mode, early, release) }()
			writeDone := make(chan error, 1)
			go func() { _, err := client.Write([]byte("early payload")); writeDone <- err }()
			select {
			case <-early:
			case <-time.After(2 * time.Second):
				t.Fatal("payload waited for Login Success")
			}
			select {
			case err := <-writeDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("early Write did not return")
			}
			close(release)
			got := make([]byte, 8)
			_, err = io.ReadFull(client, got)
			if mode == "success" || mode == "property" || mode == "unsigned" {
				if err != nil || string(got) != "response" {
					t.Fatalf("payload=%q error=%v", got, err)
				}
			} else {
				if err == nil {
					t.Fatal("invalid Login Success accepted")
				}
				if mode == "disconnect" && !strings.Contains(err.Error(), "rejected") {
					t.Fatal(err)
				}
				first := client.handshakeErr
				if first == nil || client.handshake() != first {
					t.Fatal("login failure is not sticky")
				}
				if _, again := client.Read(got); again == nil {
					t.Fatal("Read retried failed login")
				}
				if _, again := client.Write([]byte("later")); again == nil {
					t.Fatal("Write ignored failed login")
				}
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func servePipeline(peer net.Conn, profile loginProfile, key []byte, mode string, early chan<- struct{}, release <-chan struct{}) error {
	reader := bufio.NewReader(peer)
	packet, err := readPacket(reader)
	if err != nil {
		return err
	}
	var version, state Varint
	var address String
	var port UnsignedShort
	if err := packet.readFields(&version, &address, &port, &state); err != nil {
		return err
	}
	if version != 776 {
		return fmt.Errorf("client protocolVersion=%d", version)
	}
	packet, err = readPacket(reader)
	if err != nil {
		return err
	}
	var name String
	var knock UUID
	if err := packet.readFields(&name, &knock); err != nil {
		return err
	}
	if name != String(profile.Username) || knock != profile.UUID {
		return fmt.Errorf("client changed configured account identity")
	}
	if !validKnock(testPassword, address, name, knock, time.Now()) {
		return fmt.Errorf("invalid client knock")
	}
	id, public, token, auth := String(""), Bytes(key), Bytes{1, 3, 5, 7}, Boolean(true)
	if err := writePacket(peer, 1, &id, &public, &token, &auth); err != nil {
		return err
	}
	packet, err = readPacket(reader)
	if err != nil {
		return err
	}
	var secret, proof Bytes
	if err := packet.readFields(&secret, &proof); err != nil {
		return err
	}
	binding := loginBinding(version, address, port, name, knock, id, public, token)
	keys, err := verifyLoginResponse(testPassword, binding, token, secret, proof, public)
	if err != nil {
		return err
	}
	encryptedReader, err := newCryptoReader(reader, keys.clientToServer)
	if err != nil {
		return err
	}
	packet, err = readPacket(encryptedReader)
	if err != nil {
		return err
	}
	if err := validateLoginAcknowledgedPacket(packet); err != nil {
		return err
	}
	packet, err = readPacket(encryptedReader)
	if err != nil {
		return err
	}
	payload, ok, err := parseCustomPayload(packet)
	if err != nil || !ok || string(payload) != "early payload" {
		return fmt.Errorf("early payload: %q %v", payload, err)
	}
	close(early)
	<-release
	writer, err := newCryptoWriter(peer, keys.serverToClient)
	if err != nil {
		return err
	}
	if mode == "disconnect" {
		return writeDisconnectPacket(writer, `{"text":"denied"}`)
	}
	if mode == "uuid" {
		profile.UUID[0] ^= 1
	}
	if mode == "username" {
		profile.Username = "other_user"
	}
	username, count := String(profile.Username), Varint(0)
	fields := []field{&profile.UUID, &username, &count}
	if mode == "properties" {
		count = 2
	}
	if mode == "property" || mode == "unsigned" {
		count = 1
		property, value, signed, signature := String("textures"), String("ignored"), Boolean(mode == "property"), String("ignored")
		fields = append(fields, &property, &value, &signed)
		if signed {
			fields = append(fields, &signature)
		}
	}
	var wire bytes.Buffer
	if err := writePacket(&wire, 2, fields...); err != nil {
		return err
	}
	if mode == "success" || mode == "property" || mode == "unsigned" {
		channel, payload := String(packetChannel), RestBytes("response")
		if err := writePacket(&wire, configurationClientboundCustomPayload, &channel, &payload); err != nil {
			return err
		}
	}
	return writeFull(writer, wire.Bytes())
}

func TestPipelineLoginSuccessBoundaryDeadlineRetry(t *testing.T) {
	raw, peer := tcpPair(t)
	defer peer.Close()
	_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
	profile := testLoginProfile("test_user")
	client, err := newClientConn(raw, []loginProfile{profile}, testPassword, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.protocolVersion = 776
	early, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	key := testPublicKey(t)
	go func() { done <- servePipeline(peer, profile, key, "success", early, release) }()
	if _, err := client.Write([]byte("early payload")); err != nil {
		t.Fatal(err)
	}
	<-early
	_ = client.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, err = client.Read(make([]byte, 8))
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("want timeout, got %v", err)
	}
	if client.handshakeErr != nil || client.closed {
		t.Error("boundary timeout poisoned login")
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	close(release)
	got := make([]byte, 8)
	if _, err := io.ReadFull(client, got); err != nil || string(got) != "response" {
		t.Fatalf("retry=%q %v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPipelineLoginSuccessPartialTimeoutSticky(t *testing.T) {
	profile := testLoginProfile("test_user")
	var wire bytes.Buffer
	name, count := String(profile.Username), Varint(0)
	if err := writePacket(&wire, 2, &profile.UUID, &name, &count); err != nil {
		t.Fatal(err)
	}
	for _, split := range []int{0, 1, 3} {
		t.Run(fmt.Sprint(split), func(t *testing.T) {
			var encrypted bytes.Buffer
			key := streamKey{0x42}
			writer, _ := newCryptoWriter(&encrypted, key)
			if _, err := writer.Write(wire.Bytes()); err != nil {
				t.Fatal(err)
			}
			input := &interruptedFrame{head: bytes.NewReader(encrypted.Bytes()[:split]), tail: bytes.NewReader(encrypted.Bytes()[split:])}
			reader, _ := newCryptoReader(input, key)
			raw, peer := net.Pipe()
			defer peer.Close()
			client, err := newClientConn(raw, []loginProfile{profile}, testPassword, "localhost")
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.state = clientStateProxy
			client.loginReader = reader
			client.selectedProfile = profile
			err = client.validateLogin()
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("want timeout, got %v", err)
			}
			calls := input.calls
			if split == 0 {
				if err := client.validateLogin(); err != nil {
					t.Fatalf("boundary retry: %v", err)
				}
			} else {
				if client.handshakeErr != err || !client.closed {
					t.Fatal("partial timeout not sticky")
				}
				if again := client.validateLogin(); again != err || input.calls != calls {
					t.Fatal("partial login retried")
				}
				if _, again := client.Write([]byte("later")); again == nil {
					t.Fatal("Write ignored sticky login error")
				}
			}
		})
	}
}

func TestPipelineConcurrentReadWrite(t *testing.T) {
	raw, peer := tcpPair(t)
	defer raw.Close()
	defer peer.Close()
	profile := testLoginProfile("test_user")
	client, err := newClientConn(raw, []loginProfile{profile}, testPassword, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := testServerConn(peer, []loginProfile{profile}, testPassword, testPublicKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	done := make(chan error, 4)
	payload := bytes.Repeat([]byte("concurrent"), 1000)
	for _, conn := range []net.Conn{client, server} {
		go func(c net.Conn) { _, err := c.Write(payload); done <- err }(conn)
		go func(c net.Conn) {
			got := make([]byte, len(payload))
			_, err := io.ReadFull(c, got)
			if err == nil && !bytes.Equal(got, payload) {
				err = fmt.Errorf("payload mismatch")
			}
			done <- err
		}(conn)
	}
	for range 4 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
