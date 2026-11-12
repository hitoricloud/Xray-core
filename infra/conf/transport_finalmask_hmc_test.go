package conf

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/finalmask/hmc"
)

func TestHMCBuildDoesNotProbeDest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	config := &HMC{Dest: listener.Addr().String(), Password: "0123456789abcdef0123456789abcdef"}
	if _, err := config.Build(); err != nil {
		t.Fatal(err)
	}
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
	conn, err := listener.Accept()
	if err == nil {
		conn.Close()
		t.Fatal("Build alone dialed dest")
	}
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal(err)
	}
}

func TestHMCBuildProfile(t *testing.T) {
	built, err := (&HMC{
		Password: "test-password-32-bytes-minimum-value",
		Profiles: []HMCProfile{
			{
				Username: "TestUser",
				UUID:     "00112233-4455-6677-8899-aabbccddeeff",
			},
		},
	}).Build()
	if err != nil {
		t.Fatalf("build HMC config: %v", err)
	}
	config := built.(*hmc.Config)
	if len(config.Profiles) != 1 || len(config.Profiles[0].Uuid) != 16 {
		t.Fatalf("unexpected profiles: %+v", config.Profiles)
	}
}

func TestHMCBuildPasswordBounds(t *testing.T) {
	profile := HMCProfile{Username: "TestUser", UUID: "00112233445566778899aabbccddeeff"}
	for _, size := range []int{0, 31, 1025} {
		_, err := (&HMC{Password: strings.Repeat("a", size), Profiles: []HMCProfile{profile}}).Build()
		if err == nil || !strings.Contains(err.Error(), "32 to 1024 bytes") {
			t.Fatalf("password length %d: expected validation error, got %v", size, err)
		}
	}
	for _, size := range []int{32, 113, 1024} {
		if _, err := (&HMC{Password: strings.Repeat("a", size), Profiles: []HMCProfile{profile}}).Build(); err != nil {
			t.Fatalf("password length %d: %v", size, err)
		}
	}
}

func TestHMCRequiresAuthenticatedTransport(t *testing.T) {
	settings := json.RawMessage(`{"password":"test-password-32-bytes-minimum-value","hostname":"localhost","profiles":[{"username":"TestUser","uuid":"00112233445566778899aabbccddeeff","texturesValue":"value","texturesSignature":"signature"}]}`)
	for _, maskType := range []string{"hmc", "HMC", "Hmc"} {
		for _, tc := range []struct {
			name     string
			network  TransportProtocol
			security string
			valid    bool
		}{
			{name: "no security", network: "raw"},
			{name: "none", network: "tcp", security: "none"},
			{name: "REALITY", network: "raw", security: "reality"},
			{name: "websocket", network: "ws", security: "tls"},
			{name: "raw TLS", network: "raw", security: "tls", valid: true},
			{name: "tcp mixed-case TLS", network: "tcp", security: "TLS", valid: true},
		} {
			t.Run(maskType+"/"+tc.name, func(t *testing.T) {
				stream := &StreamConfig{
					Network: &tc.network, Security: tc.security,
					REALITYSettings: &REALITYConfig{Fingerprint: "chrome", PublicKey: strings.Repeat("A", 43)},
					FinalMask:       &FinalMask{Tcp: []Mask{{Type: maskType, Settings: &settings}}},
				}
				_, err := stream.Build()
				if tc.valid {
					if err != nil {
						t.Fatalf("expected valid HMC transport: %v", err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "requires raw TCP with TLS") {
					t.Fatalf("expected raw TCP/TLS requirement, got %v", err)
				}
			})
		}
	}
}

func TestHMCBuildDestAndProtocolVersion(t *testing.T) {
	profile := HMCProfile{Username: "TestUser", UUID: "00112233445566778899aabbccddeeff"}
	for _, dest := range []string{"localhost", ":25565", "localhost:0", "localhost:65536", "localhost:-1", "localhost:nope", "[::1]"} {
		if _, err := (&HMC{Dest: dest, Password: strings.Repeat("a", 32), Profiles: []HMCProfile{profile}}).Build(); err == nil {
			t.Fatalf("accepted dest %q", dest)
		}
	}
	for _, version := range []uint32{0, 1, 775, 2147483647, 2147483648, 4294967295} {
		built, err := (&HMC{Dest: "127.0.0.1:1", ProtocolVersion: version, Password: strings.Repeat("a", 32), Profiles: []HMCProfile{profile}}).Build()
		if version > 2147483647 {
			if err == nil {
				t.Fatalf("accepted version %d", version)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		config := built.(*hmc.Config)
		if config.Dest != "127.0.0.1:1" || config.ProtocolVersion != version {
			t.Fatalf("lost config: %+v", config)
		}
	}
	for _, text := range []string{`{"protocolVersion":-1}`, `{"protocolVersion":4294967296}`, `{"protocolVersion":1.5}`} {
		if err := json.Unmarshal([]byte(text), new(HMC)); err == nil {
			t.Fatalf("accepted %s", text)
		}
	}
}

func TestHMCProfileUUIDFormatsAndLegacyFields(t *testing.T) {
	for _, uuid := range []string{"00112233445566778899aabbccddeeff", "00112233-4455-6677-8899-AABBCCDDEEFF"} {
		var profile HMCProfile
		text := `{"username":"TestUser","uuid":"` + uuid + `","texturesValue":"ignored","texturesSignature":"ignored"}`
		if err := json.Unmarshal([]byte(text), &profile); err != nil {
			t.Fatal(err)
		}
		built, err := profile.Build()
		if err != nil || len(built.Uuid) != 16 || built.Uuid[15] != 0xff || built.Username != "TestUser" {
			t.Fatalf("UUID not preserved: %q %v", uuid, err)
		}
	}
	for _, uuid := range []string{"", "invalid", "00112233445566778899aabbccddee", "00112233445566778899aabbccddeeff00", "00112233_4455-6677-8899-aabbccddeeff", "00112233445566778899aabbccddeefg"} {
		if _, err := (&HMCProfile{Username: "TestUser", UUID: uuid}).Build(); err == nil {
			t.Fatalf("accepted UUID %q", uuid)
		}
	}
	for _, username := range []string{"ab", "abcdefghijklmnopq", "bad!name", ""} {
		if _, err := (&HMCProfile{Username: username, UUID: "00112233445566778899aabbccddeeff"}).Build(); err == nil {
			t.Fatalf("accepted username %q", username)
		}
	}
}

func TestHMCBuildAllowsNoProfiles(t *testing.T) {
	built, err := (&HMC{Password: "test-password-32-bytes-minimum-value"}).Build()
	if err != nil {
		t.Fatal(err)
	}
	config := built.(*hmc.Config)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	server, err := config.WrapConnServer(a)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := config.WrapConnClient(b, nil, nil)
	if err != nil {
		t.Fatalf("client must derive stable profiles when none are configured: %v", err)
	}
	defer client.Close()
}
