package conf

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/transport/internet/finalmask/hmc"
)

const (
	hmcUserID    = "00112233-4455-4677-8899-aabbccddeeff"
	hmcPassword  = "test-password-32-bytes-minimum-value"
	hmcMaskBlock = `"finalmask":{"tcp":[{"type":"hmc","settings":{"password":"` + hmcPassword + `","hostname":"localhost"}}]}`
)

// Real X25519 pair, as `xray vlessenc` produces: the server holds the private key.
var vencServer, vencClient = func() (string, string) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	enc := base64.RawURLEncoding
	return "mlkem768x25519plus.native.600s." + enc.EncodeToString(key.Bytes()),
		"mlkem768x25519plus.native.0rtt." + enc.EncodeToString(key.PublicKey().Bytes())
}()

func hmcStream(security string) string {
	extra := ""
	if security != "" {
		extra = `"security":"` + security + `",`
	}
	return `"streamSettings":{"network":"raw",` + extra + hmcMaskBlock + `}`
}

func buildHMCInbound(t *testing.T, protocol, settings, stream string) error {
	t.Helper()
	var detour InboundDetourConfig
	raw := `{"protocol":"` + protocol + `","listen":"127.0.0.1","port":10443,"settings":` + settings + `,` + stream + `}`
	if err := json.Unmarshal([]byte(raw), &detour); err != nil {
		t.Fatal(err)
	}
	_, err := detour.Build()
	return err
}

func buildHMCOutbound(t *testing.T, protocol, settings, stream string) error {
	t.Helper()
	var detour OutboundDetourConfig
	raw := `{"protocol":"` + protocol + `","settings":` + settings + `,` + stream + `}`
	if err := json.Unmarshal([]byte(raw), &detour); err != nil {
		t.Fatal(err)
	}
	_, err := detour.Build()
	return err
}

func vlessInbound(decryption string) string {
	return `{"clients":[{"id":"` + hmcUserID + `"}],"decryption":"` + decryption + `"}`
}

func vlessOutbound(encryption string) string {
	return `{"vnext":[{"address":"127.0.0.1","port":10443,"users":[{"id":"` + hmcUserID + `","encryption":"` + encryption + `"}]}]}`
}

func vlessOutboundSimple(encryption string) string {
	return `{"address":"127.0.0.1","port":10443,"id":"` + hmcUserID + `","encryption":"` + encryption + `"}`
}

func TestHMCWithVLESSEncryptionNeedsNoTLS(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func() error
		ok    bool
	}{
		{"inbound encrypted, no security", func() error { return buildHMCInbound(t, "vless", vlessInbound(vencServer), hmcStream("")) }, true},
		{"inbound encrypted, security none", func() error { return buildHMCInbound(t, "vless", vlessInbound(vencServer), hmcStream("none")) }, true},
		{"inbound decryption none, no security", func() error { return buildHMCInbound(t, "vless", vlessInbound("none"), hmcStream("")) }, false},
		{"outbound encrypted (vnext), no security", func() error { return buildHMCOutbound(t, "vless", vlessOutbound(vencClient), hmcStream("")) }, true},
		{"outbound encrypted (simple), no security", func() error { return buildHMCOutbound(t, "vless", vlessOutboundSimple(vencClient), hmcStream("")) }, true},
		{"outbound encryption none, no security", func() error { return buildHMCOutbound(t, "vless", vlessOutbound("none"), hmcStream("")) }, false},
		{"outbound encryption none, simple, no security", func() error { return buildHMCOutbound(t, "vless", vlessOutboundSimple("none"), hmcStream("")) }, false},
		{"other protocol without TLS", func() error {
			return buildHMCInbound(t, "trojan", `{"clients":[{"password":"x"}]}`, hmcStream(""))
		}, false},
		{"encrypted vless under websocket stays rejected", func() error {
			return buildHMCInbound(t, "vless", vlessInbound(vencServer), `"streamSettings":{"network":"ws",`+hmcMaskBlock+`}`)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.build()
			if tc.ok && err != nil {
				t.Fatalf("expected the build to succeed: %v", err)
			}
			if !tc.ok && (err == nil || !strings.Contains(err.Error(), "hmc requires raw TCP")) {
				t.Fatalf("expected the HMC transport guard to reject, got %v", err)
			}
		})
	}
}

func TestHMCWithoutEncryptionStillAcceptsTLS(t *testing.T) {
	if err := buildHMCInbound(t, "vless", vlessInbound("none"), hmcStream("tls")); err != nil {
		t.Fatalf("TLS must remain a valid inner protection: %v", err)
	}
}

func TestHMCDerivedAccountsArePerVLESSUser(t *testing.T) {
	build := func(id string) []string {
		var detour OutboundDetourConfig
		raw := `{"protocol":"vless","settings":{"address":"127.0.0.1","port":10443,"id":"` + id + `","encryption":"` + vencClient + `"},` + hmcStream("") + `}`
		if err := json.Unmarshal([]byte(raw), &detour); err != nil {
			t.Fatal(err)
		}
		built, err := detour.Build()
		if err != nil {
			t.Fatal(err)
		}
		sender, err := built.SenderSettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, message := range sender.(*proxyman.SenderConfig).StreamSettings.Tcpmasks {
			instance, err := message.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			for _, profile := range instance.(*hmc.Config).Profiles {
				names = append(names, profile.Username)
			}
		}
		return names
	}
	one, two := build(hmcUserID), build("11112222-3333-4444-8888-aabbccddeeff")
	if len(one) != 4 || len(two) != 4 {
		t.Fatalf("expected four derived accounts per client, got %d and %d", len(one), len(two))
	}
	for _, a := range one {
		for _, b := range two {
			if a == b {
				t.Fatalf("two VLESS users share derived account %q", a)
			}
		}
	}
	if again := build(hmcUserID); again[0] != one[0] {
		t.Fatal("one user's derived accounts must be stable across builds")
	}
}

func TestHMCHostnameValidation(t *testing.T) {
	profile := hmcTestProfiles()
	for _, hostname := range []string{"bad\u0000host", strings.Repeat("a", 254)} {
		if _, err := (&HMC{Password: hmcPassword, Hostname: hostname, Profiles: profile}).Build(); err == nil {
			t.Fatalf("accepted hostname %q", hostname)
		}
	}
	if _, err := (&HMC{Password: hmcPassword, Hostname: strings.Repeat("a", 253), Profiles: profile}).Build(); err != nil {
		t.Fatal(err)
	}
}

func hmcTestProfiles() []HMCProfile {
	return []HMCProfile{{Username: "TestUser", UUID: hmcUserID}}
}
