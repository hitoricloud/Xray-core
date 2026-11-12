package hmc

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func poolProfiles(n int) []loginProfile {
	profiles := make([]loginProfile, n)
	for i := range profiles {
		profiles[i] = testLoginProfile(fmt.Sprintf("Account_%02d", i))
	}
	return profiles
}

func poolLeaseCounts(p *profilePool) []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]int(nil), p.leases...)
}

func TestPoolLeasesFreeBeforeReuseAndReleaseOnce(t *testing.T) {
	profiles := poolProfiles(8)
	password := testPassword + t.Name()
	p := poolFor(password, profiles)
	reversed := append([]loginProfile(nil), profiles...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	if p != poolFor(password, reversed) || p == poolFor(password+"different", profiles) {
		t.Fatal("pool key not canonical/password scoped")
	}
	clients := make([]*clientConn, 0, len(profiles))
	for range profiles {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		client, err := newClientConn(a, reversed, password, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, client)
		t.Cleanup(func() { client.Close() })
	}
	seen := map[loginProfile]bool{}
	for _, client := range clients {
		if seen[client.selectedProfile] {
			t.Fatal("duplicate while a free account existed")
		}
		seen[client.selectedProfile] = true
	}
	for _, n := range poolLeaseCounts(p) {
		if n != 1 {
			t.Fatalf("lease counts=%v", poolLeaseCounts(p))
		}
	}
	extra, release, err := p.lease()
	if err != nil || !seen[extra] {
		t.Fatalf("exhaustion must reuse an account: %v", err)
	}
	clients[0].Close()
	clients[0].Close()
	release()
	release()
	profile, releaseAgain, err := p.lease()
	if err != nil || profile != clients[0].selectedProfile {
		t.Fatalf("released free account not preferred: %v", err)
	}
	releaseAgain()
	for _, client := range clients {
		client.Close()
	}
	for _, n := range poolLeaseCounts(p) {
		if n != 0 {
			t.Fatalf("double/missing release: %v", poolLeaseCounts(p))
		}
	}
}

func TestPoolReleaseOnHandshakeFailure(t *testing.T) {
	profiles := poolProfiles(2)
	password := testPassword + t.Name()
	p := poolFor(password, profiles)
	a, b := net.Pipe()
	client, err := newClientConn(a, profiles, password, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	b.Close()
	if err := client.handshake(); err == nil {
		t.Fatal("handshake succeeded with closed peer")
	}
	for _, n := range poolLeaseCounts(p) {
		if n != 0 {
			t.Fatal("failed handshake retained lease")
		}
	}
	client.Close()
	for _, n := range poolLeaseCounts(p) {
		if n != 0 {
			t.Fatal("failure followed by Close released twice")
		}
	}
}

func TestPoolReleaseOnDeferredLoginFailure(t *testing.T) {
	profiles := poolProfiles(2)
	password := testPassword + t.Name()
	p := poolFor(password, profiles)
	a, b := net.Pipe()
	defer b.Close()
	client, err := newClientConn(a, profiles, password, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	profile := client.selectedProfile
	profile.UUID[0] ^= 1
	name, count := String(profile.Username), Varint(0)
	wire, err := encodePacket(2, &profile.UUID, &name, &count)
	if err != nil {
		t.Fatal(err)
	}
	client.state = clientStateProxy
	client.loginReader = bytes.NewReader(wire)
	if err := client.validateLogin(); err == nil || !client.closed {
		t.Fatalf("bad identity not rejected/closed: %v", err)
	}
	for _, n := range poolLeaseCounts(p) {
		if n != 0 {
			t.Fatal("deferred login failure retained lease")
		}
	}
}

func TestPoolConcurrentLeases(t *testing.T) {
	profiles := poolProfiles(32)
	p := poolFor(testPassword+t.Name(), profiles)
	for range 10 {
		var wg sync.WaitGroup
		var mu sync.Mutex
		seen := map[loginProfile]bool{}
		ready, release := make(chan struct{}, len(profiles)), make(chan struct{})
		for range profiles {
			wg.Add(1)
			go func() {
				defer wg.Done()
				profile, done, err := p.lease()
				if err != nil {
					t.Error(err)
					ready <- struct{}{}
					return
				}
				mu.Lock()
				if seen[profile] {
					t.Error("duplicate concurrent free lease")
				}
				seen[profile] = true
				mu.Unlock()
				ready <- struct{}{}
				<-release
				done()
				done()
			}()
		}
		for range profiles {
			<-ready
		}
		counts := make(map[loginProfile]int)
		for range 1024 {
			profile, done, err := p.lease()
			if err != nil {
				t.Fatal(err)
			}
			counts[profile]++
			done()
		}
		for _, profile := range profiles {
			if counts[profile] < 10 || counts[profile] > 60 {
				t.Errorf("implausible exhaustion selection: %d/1024", counts[profile])
			}
		}
		close(release)
		wg.Wait()
		for _, n := range poolLeaseCounts(p) {
			if n != 0 {
				t.Fatal("concurrent release lost")
			}
		}
	}
}

type wireRecordingConn struct {
	net.Conn
	mu   sync.Mutex
	wire bytes.Buffer
}

func (c *wireRecordingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.wire.Write(p[:n])
	c.mu.Unlock()
	return n, err
}

func TestPoolWireUsesFixedRealIdentityAndServerWithoutProfiles(t *testing.T) {
	profile := testLoginProfile("RealAccount")
	config := &Config{Password: testPassword + t.Name(), CamouflagePublicKey: testPublicKey(t), Profiles: []*Profile{{Username: profile.Username, Uuid: profile.UUID[:]}}}
	serverConfig := &Config{Password: config.Password, CamouflagePublicKey: config.CamouflagePublicKey}
	for _, host := range []string{"dest.example", "", "dest.example", "", "dest.example"} {
		a, b := tcpPair(t)
		recording := &wireRecordingConn{Conn: a}
		config.Hostname = host
		wrapped, err := config.WrapConnClient(recording, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		client := wrapped.(*clientConn)
		server, err := serverConfig.WrapConnServer(b)
		if err != nil {
			t.Fatal(err)
		}
		_ = client.SetDeadline(time.Now().Add(3 * time.Second))
		_ = server.SetDeadline(time.Now().Add(3 * time.Second))
		done := make(chan error, 1)
		go func() { done <- server.(*serverConn).handshake() }()
		if err := client.handshake(); err != nil {
			t.Fatal(err)
		}
		if err := client.validateLogin(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		recording.mu.Lock()
		wire := bytes.Clone(recording.wire.Bytes())
		recording.mu.Unlock()
		r := bytes.NewReader(wire)
		handshake, err := readPacket(r)
		if err != nil {
			t.Fatal(err)
		}
		var version, state Varint
		var address String
		var port UnsignedShort
		if err := handshake.readFields(&version, &address, &port, &state); err != nil {
			t.Fatal(err)
		}
		start, err := readPacket(r)
		if err != nil {
			t.Fatal(err)
		}
		var name String
		var uuid UUID
		if err := start.readFields(&name, &uuid); err != nil {
			t.Fatal(err)
		}
		if name != String(profile.Username) || uuid != profile.UUID {
			t.Fatal("wire identity randomized")
		}
		if host == "" {
			host, _, _ = net.SplitHostPort(a.RemoteAddr().String())
		}
		if string(address[:len(host)]) != host || !validKnock(config.Password, address, name, uuid, time.Now()) {
			t.Fatalf("bad wire address %q", address)
		}
		client.Close()
		server.Close()
	}
}
