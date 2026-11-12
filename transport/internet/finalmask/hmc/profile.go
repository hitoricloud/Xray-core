package hmc

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"regexp"
)

const derivedProfileCount = 4

const usernameAlphabet = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

// Without configured profiles the client uses stable pseudo-accounts derived from
// the password and a per-client seed (the VLESS user id). Not Mojang accounts.
func derivedProfiles(password, seed string, count int) []loginProfile {
	profiles := make([]loginProfile, 0, count)
	for i := 0; i < count; i++ {
		mac := hmac.New(sha256.New, passwordSecret(password))
		mac.Write([]byte("hmc1 identity"))
		mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(seed))))
		mac.Write([]byte(seed))
		mac.Write(binary.BigEndian.AppendUint32(nil, uint32(i)))
		sum := mac.Sum(nil)
		name := make([]byte, 6+int(sum[0])%9)
		for j := range name {
			name[j] = usernameAlphabet[int(sum[1+j])%len(usernameAlphabet)]
		}
		if name[0] >= '0' && name[0] <= '9' || name[0] == '_' {
			name[0] = 'a' + sum[15]%26
		}
		profile := loginProfile{Username: string(name)}
		copy(profile.UUID[:], sum[16:])
		profile.UUID[6] = profile.UUID[6]&0x0f | 0x40
		profile.UUID[8] = profile.UUID[8]&0x3f | 0x80
		profiles = append(profiles, profile)
	}
	return profiles
}

type loginProfile struct {
	Username string
	UUID     UUID
}

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{3,16}$`)

func profilesFromConfig(configured []*Profile) ([]loginProfile, error) {
	profiles := make([]loginProfile, 0, len(configured))
	for _, configuredProfile := range configured {
		if configuredProfile == nil || !usernamePattern.MatchString(configuredProfile.Username) || len(configuredProfile.Uuid) != 16 {
			return nil, fmt.Errorf("invalid profile: expected Minecraft username and 16-byte UUID")
		}
		profile := loginProfile{Username: configuredProfile.Username, UUID: UUID(configuredProfile.Uuid)}
		duplicate := false
		for _, previous := range profiles {
			if previous.Username == profile.Username || previous.UUID == profile.UUID {
				if previous != profile {
					return nil, fmt.Errorf("conflicting profile identity")
				}
				duplicate = true
			}
		}
		if !duplicate {
			profiles = append(profiles, profile)
		}
	}
	return profiles, nil
}

func readLoginSuccess(packet *mcPacket) (loginProfile, error) {
	var profile loginProfile
	var username String
	var count Varint
	r := bytes.NewReader(packet.data)
	for _, f := range []field{&profile.UUID, &username, &count} {
		if err := f.readFrom(r); err != nil {
			return loginProfile{}, err
		}
	}
	if count < 0 || count > 1 {
		return loginProfile{}, fmt.Errorf("invalid login profile properties")
	}
	if count == 1 {
		var name, value, signature String
		var signed Boolean
		for _, f := range []field{&name, &value, &signed} {
			if err := f.readFrom(r); err != nil {
				return loginProfile{}, err
			}
		}
		if signed {
			if err := signature.readFrom(r); err != nil {
				return loginProfile{}, err
			}
		}
	}
	if r.Len() != 0 {
		return loginProfile{}, fmt.Errorf("trailing login profile data")
	}
	profile.Username = string(username)
	return profile, nil
}

// DerivedProfiles returns the pseudo-accounts a client with this seed would use.
func DerivedProfiles(password, seed string) []*Profile {
	derived := derivedProfiles(password, seed, derivedProfileCount)
	profiles := make([]*Profile, len(derived))
	for i, profile := range derived {
		profiles[i] = &Profile{Username: profile.Username, Uuid: append([]byte(nil), profile.UUID[:]...)}
	}
	return profiles
}
