package conf

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/xtls/xray-core/transport/internet/finalmask/hmc"
	"google.golang.org/protobuf/proto"
)

type HMC struct {
	Dest            string       `json:"dest"`
	ProtocolVersion uint32       `json:"protocolVersion"`
	Hostname        string       `json:"hostname"`
	Profiles        []HMCProfile `json:"profiles"`
	Password        string       `json:"password"`
	MaxPreAuth      uint32       `json:"maxPreAuth"`
	MaxPreAuthPerIP uint32       `json:"maxPreAuthPerIP"`
	MaxRelaysPerIP  uint32       `json:"maxRelaysPerIP"`
	RatePerIP       uint32       `json:"ratePerIP"`
	BurstPerIP      uint32       `json:"burstPerIP"`
	TrustedSources  []string     `json:"trustedSources"`
}

type HMCProfile struct {
	Username string `json:"username"`
	UUID     string `json:"uuid"`
}

var hmcUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{3,16}$`)

func (c *HMCProfile) Build() (*hmc.Profile, error) {
	if !hmcUsernamePattern.MatchString(c.Username) {
		return nil, fmt.Errorf("invalid minecraft profile username: %q", c.Username)
	}
	uuid := c.UUID
	if len(uuid) == 36 && uuid[8] == '-' && uuid[13] == '-' && uuid[18] == '-' && uuid[23] == '-' {
		uuid = uuid[:8] + uuid[9:13] + uuid[14:18] + uuid[19:23] + uuid[24:]
	}
	decoded, err := hex.DecodeString(uuid)
	if err != nil || len(decoded) != 16 {
		return nil, fmt.Errorf("invalid minecraft profile UUID: expected 32 hex digits or dashed UUID")
	}
	return &hmc.Profile{Username: c.Username, Uuid: decoded}, nil
}

func (c *HMC) Build() (proto.Message, error) {
	config := &hmc.Config{Password: c.Password, Hostname: c.Hostname, Dest: c.Dest, ProtocolVersion: c.ProtocolVersion,
		MaxPreAuth: c.MaxPreAuth, MaxPreAuthPerIp: c.MaxPreAuthPerIP, MaxRelaysPerIp: c.MaxRelaysPerIP, RatePerIp: c.RatePerIP, BurstPerIp: c.BurstPerIP, TrustedSources: append([]string(nil), c.TrustedSources...)}
	if err := config.ValidateAdmission(); err != nil {
		return nil, err
	}
	if c.ProtocolVersion > 2147483647 {
		return nil, fmt.Errorf("invalid HMC protocolVersion")
	}
	if len(c.Hostname) > 253 || strings.ContainsRune(c.Hostname, 0) {
		return nil, fmt.Errorf("invalid HMC hostname: at most 253 bytes and no NUL")
	}
	if c.Dest != "" {
		if err := hmc.ValidateDest(c.Dest); err != nil {
			return nil, err
		}
	}
	if len(c.Password) < hmc.MinPasswordLength || len(c.Password) > hmc.MaxPasswordLength {
		return nil, fmt.Errorf("minecraft password must be %d to %d bytes and randomly generated", hmc.MinPasswordLength, hmc.MaxPasswordLength)
	}
	profiles := make([]*hmc.Profile, 0, len(c.Profiles))
	for i := range c.Profiles {
		profile, err := c.Profiles[i].Build()
		if err != nil {
			return nil, fmt.Errorf("build minecraft profile %d: %w", i, err)
		}
		profiles = append(profiles, profile)
	}
	// The camouflage private key is discarded.
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, fmt.Errorf("generate camouflage rsa key: %w", err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal camouflage rsa public key: %w", err)
	}
	hmc.PrepareSecret(c.Password)
	config.CamouflagePublicKey, config.Profiles = publicKey, profiles
	return config, nil
}
