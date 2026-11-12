package conf

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/transport/internet/finalmask/hmc"
	"google.golang.org/protobuf/proto"
)

func TestHMCAdmissionTrustedSourcesJSONAndProtobuf(t *testing.T) {
	var input HMC
	if err := json.Unmarshal([]byte(`{"password":"0123456789abcdef0123456789abcdef","trustedSources":["192.0.2.1","2001:db8::/48","::ffff:192.0.2.0/120","unix"]}`), &input); err != nil {
		t.Fatal(err)
	}
	built, err := input.Build()
	if err != nil {
		t.Fatal(err)
	}
	config := built.(*hmc.Config)
	if len(config.TrustedSources) != 4 || config.TrustedSources[3] != "unix" {
		t.Fatal("trustedSources lost")
	}
	input.TrustedSources[0] = "198.51.100.1"
	if config.TrustedSources[0] != "192.0.2.1" {
		t.Fatal("built config aliases JSON")
	}
	wire, err := proto.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(hmc.Config)
	if err := proto.Unmarshal(wire, decoded); err != nil || !proto.Equal(config, decoded) {
		t.Fatalf("protobuf roundtrip: %v", err)
	}
	field := config.ProtoReflect().Descriptor().Fields().ByName("trusted_sources")
	if field.Number() != 19 || !field.IsList() {
		t.Fatal("trusted_sources descriptor")
	}
	for _, source := range []string{"", "bad", "192.0.2.1/33", "2001:db8::/129", "127.0.0.1:80", "UNIX", "fe80::1%eth0", "192.0.2.1\x00unix", " unix", "0.0.0.0/0", "::/0", "1.2.3.4/7", "2001:db8::/31", "::ffff:1.2.3.4/103", "::ffff:1.2.3.4/95"} {
		input.TrustedSources = []string{source}
		if _, err := input.Build(); err == nil {
			t.Fatalf("bad source accepted: %q", source)
		}
		if (&hmc.Config{TrustedSources: input.TrustedSources}).ValidateAdmission() == nil {
			t.Fatalf("protobuf accepted: %q", source)
		}
	}
	input.TrustedSources = strings.Split(strings.Repeat("unix,", 256), ",")[:256]
	if _, err := input.Build(); err != nil {
		t.Fatalf("256 sources: %v", err)
	}
	input.TrustedSources = append(input.TrustedSources, "unix")
	if _, err := input.Build(); err == nil {
		t.Fatal("257 sources accepted")
	}
	if (&hmc.Config{TrustedSources: input.TrustedSources}).ValidateAdmission() == nil {
		t.Fatal("protobuf accepted 257 sources")
	}
	for _, text := range []string{`{"trustedSources":"unix"}`, `{"trustedSources":[1]}`, `{"trustedSources":[{}]}`} {
		if err := json.Unmarshal([]byte(text), new(HMC)); err == nil {
			t.Fatalf("bad JSON type accepted: %s", text)
		}
	}
}
