package conf

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/xtls/xray-core/transport/internet/finalmask/hmc"
	"google.golang.org/protobuf/proto"
)

func TestHMCAdmissionOverridesAndValidation(t *testing.T) {
	keys := []string{"maxPreAuth", "maxPreAuthPerIP", "maxRelaysPerIP", "ratePerIP", "burstPerIP"}
	var input HMC
	if err := json.Unmarshal([]byte(`{"password":"0123456789abcdef0123456789abcdef","maxPreAuth":8,"maxPreAuthPerIP":3,"maxRelaysPerIP":2,"ratePerIP":5,"burstPerIP":11}`), &input); err != nil {
		t.Fatal(err)
	}
	built, err := input.Build()
	if err != nil {
		t.Fatal(err)
	}
	config := built.(*hmc.Config)
	if config.MaxPreAuth != 8 || config.MaxPreAuthPerIp != 3 || config.MaxRelaysPerIp != 2 || config.RatePerIp != 5 || config.BurstPerIp != 11 {
		t.Fatalf("overrides lost: %v", config)
	}
	wire, err := proto.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(hmc.Config)
	if err := proto.Unmarshal(wire, decoded); err != nil || !proto.Equal(config, decoded) {
		t.Fatalf("protobuf roundtrip: %v", err)
	}
	for _, key := range keys {
		for _, value := range []string{"-1", "4294967296", "1.5", `"1"`} {
			if err := json.Unmarshal([]byte(fmt.Sprintf(`{"%s":%s}`, key, value)), new(HMC)); err == nil {
				t.Fatalf("accepted %s=%s", key, value)
			}
		}
		for _, value := range []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 1000000, 1000001, 4294967295} {
			text := fmt.Sprintf(`{"password":"0123456789abcdef0123456789abcdef","%s":%d}`, key, value)
			var input HMC
			if err := json.Unmarshal([]byte(text), &input); err != nil {
				t.Fatal(err)
			}
			_, err := input.Build()
			if (err == nil) != (value <= 1000000 && (key != "maxPreAuth" || value == 0 || value >= 8)) {
				t.Fatalf("%s=%d: %v", key, value, err)
			}
		}
	}
}
