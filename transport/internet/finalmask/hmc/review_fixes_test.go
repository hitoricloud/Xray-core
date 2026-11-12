package hmc

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func TestPoolKeyIsInjective(t *testing.T) {
	a := loginProfile{Username: "AlphaOne", UUID: UUID{1}}
	b := loginProfile{Username: "BravoTwo", UUID: UUID{2}}
	p1 := testPassword + "-collide-base"
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(a.Username)))
	frame = append(frame, a.Username...)
	frame = append(frame, a.UUID[:]...)
	if poolFor(p1, []loginProfile{a, b}) == poolFor(p1+string(frame), []loginProfile{b}) {
		t.Fatal("a password that embeds an encoded profile must not share a pool")
	}
}

// Fix the stretch so thousands of throwaway passwords stay cheap in tests.
func stubStretch(password string) {
	entry := &stretchedPassword{key: []byte(password + "-stretched-0123456789abcdef")[:32]}
	entry.once.Do(func() {})
	stretchedPasswords.Store(password, entry)
}

func TestDerivedProfileNameIsIndependentOfUUID(t *testing.T) {
	const passwords = 5000
	match, lower := 0, 0
	for i := 0; i < passwords; i++ {
		var key [16]byte
		_, _ = rand.Read(key[:])
		password := string(key[:]) + "review"
		stubStretch(password)
		for _, profile := range derivedProfiles(password, "", 4) {
			if c := profile.Username[0]; c >= 'a' && c <= 'z' {
				lower++
				if c == 'a'+profile.UUID[4]%26 {
					match++
				}
			}
		}
		stretchedPasswords.Delete(password)
	}
	// Independent letters match in ~1/26 = 3.8% of cases; the old bug gave 16%.
	if rate := float64(match) / float64(lower); rate > 0.06 {
		t.Fatalf("name's first letter tracks a UUID byte: %.3f", rate)
	}
}

func TestDerivedProfilesAreDisjointPerClientSeed(t *testing.T) {
	first, second := derivedProfiles(testPassword, "client-one", 4), derivedProfiles(testPassword, "client-two", 4)
	seen := map[string]bool{}
	for _, profile := range first {
		seen[profile.Username] = true
	}
	for _, profile := range second {
		if seen[profile.Username] {
			t.Fatalf("two clients of one server share account %q", profile.Username)
		}
	}
	again := derivedProfiles(testPassword, "client-one", 4)
	for i := range first {
		if first[i] != again[i] {
			t.Fatal("one client's accounts must be stable")
		}
	}
	exported := DerivedProfiles(testPassword, "client-one")
	if len(exported) != 4 || exported[0].Username != first[0].Username || len(exported[0].Uuid) != 16 {
		t.Fatal("exported derivation must match the runtime derivation")
	}
}
