package hmc

import (
	"bytes"
	"testing"
)

func TestProfilesFromConfig(t *testing.T) {
	if profiles, err := profilesFromConfig(nil); err != nil || len(profiles) != 0 {
		t.Fatalf("server may omit profiles: %v", err)
	}
	uuid := bytes.Repeat([]byte{0x2a}, 16)
	profiles, err := profilesFromConfig([]*Profile{{Username: "RealUser", Uuid: uuid}, {Username: "RealUser", Uuid: uuid}})
	if err != nil || len(profiles) != 1 || profiles[0] != (loginProfile{Username: "RealUser", UUID: UUID(uuid)}) {
		t.Fatalf("identity not preserved/deduplicated: %+v %v", profiles, err)
	}
	for _, bad := range []*Profile{nil, {Username: "x", Uuid: uuid}, {Username: "bad!name", Uuid: uuid}, {Username: "RealUser"}, {Username: "RealUser", Uuid: []byte{1}}, {Username: "RealUser", Uuid: make([]byte, 17)}} {
		if _, err := profilesFromConfig([]*Profile{bad}); err == nil {
			t.Fatalf("accepted invalid profile: %v", bad)
		}
	}
	for _, conflict := range []*Profile{{Username: "OtherUser", Uuid: uuid}, {Username: "RealUser", Uuid: make([]byte, 16)}} {
		if _, err := profilesFromConfig([]*Profile{{Username: "RealUser", Uuid: uuid}, conflict}); err == nil {
			t.Fatal("accepted conflicting identities")
		}
	}
}

func TestLoginSuccessProperties(t *testing.T) {
	profile := testLoginProfile("RealUser")
	for _, mode := range []string{"zero", "unsigned", "signed", "two", "negative", "truncated", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			name, count := String(profile.Username), Varint(0)
			property, value, signed, signature := String("arbitrary"), String("ignored"), Boolean(false), String("ignored-signature")
			fields := []field{&profile.UUID, &name, &count}
			switch mode {
			case "unsigned", "signed", "truncated":
				count = 1
				fields = append(fields, &property, &value, &signed)
				if mode != "unsigned" {
					signed = true
					if mode == "signed" {
						fields = append(fields, &signature)
					}
				}
			case "two":
				count = 2
			case "negative":
				count = -1
			case "trailing":
				fields = append(fields, &property)
			}
			wire, err := encodePacket(2, fields...)
			if err != nil {
				t.Fatal(err)
			}
			packet, err := readPacket(bytes.NewReader(wire))
			if err != nil {
				t.Fatal(err)
			}
			got, err := readLoginSuccess(packet)
			valid := mode == "zero" || mode == "unsigned" || mode == "signed"
			if valid && (err != nil || got != profile) || !valid && err == nil {
				t.Fatalf("profile=%+v error=%v", got, err)
			}
		})
	}
}
