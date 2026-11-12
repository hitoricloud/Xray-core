package hmc

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestDerivedProfilesAreStableDistinctAndValid(t *testing.T) {
	first, again := derivedProfiles(testPassword, "", 4), derivedProfiles(testPassword, "", 4)
	other := derivedProfiles(testPassword+"x", "", 4)
	seen := map[string]bool{}
	for i, profile := range first {
		if profile != again[i] {
			t.Fatal("derived profiles must be stable for one password")
		}
		if !usernamePattern.MatchString(profile.Username) || len(profile.Username) < 6 {
			t.Fatalf("invalid derived username %q", profile.Username)
		}
		if profile.UUID[6]>>4 != 4 || profile.UUID[8]>>6 != 2 {
			t.Fatalf("derived UUID is not v4-shaped: %x", profile.UUID)
		}
		if first[i] == other[i] || seen[profile.Username] {
			t.Fatal("profiles must be distinct across indexes and passwords")
		}
		seen[profile.Username] = true
	}
}

func TestClientWithoutConfiguredProfilesHandshakes(t *testing.T) {
	config := &Config{Password: testPassword, Hostname: "localhost", CamouflagePublicKey: testPublicKey(t)}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			received <- err
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		server, err := config.WrapConnServer(raw)
		if err != nil {
			received <- err
			return
		}
		buf := make([]byte, 5)
		if _, err = io.ReadFull(server, buf); err == nil && string(buf) != "hello" {
			err = io.ErrUnexpectedEOF
		}
		received <- err
	}()
	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	client, err := config.WrapConnClient(raw, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := <-received; err != nil {
		t.Fatalf("server did not receive the payload from a client with derived profiles: %v", err)
	}
}
