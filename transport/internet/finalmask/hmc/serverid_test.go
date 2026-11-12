package hmc

import "testing"

func TestFreshServerIDMimicsSignedHexAndKeepsOtherFormats(t *testing.T) {
	if got := freshServerID(""); got != "" {
		t.Fatalf("empty id must stay empty, got %q", got)
	}
	if got := freshServerID("not-hex-format!"); got != "not-hex-format!" {
		t.Fatalf("unknown format must be reused, got %q", got)
	}
	seen := map[String]bool{}
	for i := 0; i < 200; i++ {
		id := freshServerID("-7354fe051de809b2")
		if !signedHexID.MatchString(string(id)) {
			t.Fatalf("generated id %q is not signed hex", id)
		}
		seen[id] = true
	}
	if len(seen) < 190 {
		t.Fatalf("server ids repeat too often: %d distinct of 200", len(seen))
	}
}
