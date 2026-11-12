package hmc

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"weak"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

const (
	MinPasswordLength = 32
	MaxPasswordLength = 1024
)

func (c *Config) TCP() {
}

func (c *Config) validatePassword() error {
	if err := c.ValidateAdmission(); err != nil {
		return err
	}
	if c.ProtocolVersion > 2147483647 {
		return fmt.Errorf("invalid HMC protocol version")
	}
	if c.Dest != "" {
		if err := ValidateDest(c.Dest); err != nil {
			return err
		}
	}
	if len(c.Password) < MinPasswordLength || len(c.Password) > MaxPasswordLength {
		return fmt.Errorf("minecraft finalmask: password must be %d to %d bytes and randomly generated", MinPasswordLength, MaxPasswordLength)
	}
	return nil
}

func (c *Config) WrapConnClient(conn net.Conn, _ *xnet.Destination, _ *finalmask.Dialer) (net.Conn, error) {
	if err := c.validatePassword(); err != nil {
		return nil, err
	}
	profiles, err := profilesFromConfig(c.Profiles)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}
	if len(profiles) == 0 {
		profiles = derivedProfiles(c.Password, "", derivedProfileCount)
	}
	cc, err := newClientConn(conn, profiles, c.Password, c.Hostname)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}
	cc.protocolVersion = c.ProtocolVersion

	return cc, nil
}

type cachedServerAdmission struct {
	once    sync.Once
	mu      sync.Mutex
	limiter *admissionLimiter
	err     error
}

var serverAdmissions sync.Map

func (c *Config) serverAdmission() (*admissionLimiter, error) {
	defer runtime.KeepAlive(c)
	key := weak.Make(c)
	entry, ok := serverAdmissions.Load(key)
	if !ok {
		var loaded bool
		entry, loaded = serverAdmissions.LoadOrStore(key, new(cachedServerAdmission))
		if !loaded {
			runtime.AddCleanup(c, func(key weak.Pointer[Config]) { serverAdmissions.Delete(key) }, key)
		}
	}
	cached := entry.(*cachedServerAdmission)
	cached.once.Do(func() {
		cached.err = c.validatePassword()
		if cached.err == nil {
			cached.limiter = c.admission()
		}
	})
	cached.mu.Lock()
	defer cached.mu.Unlock()
	if cached.limiter != nil {
		cached.limiter.mu.Lock()
		retired := cached.limiter.retired
		cached.limiter.mu.Unlock()
		if retired {
			cached.limiter = c.admission()
		}
	}
	return cached.limiter, cached.err
}

func (c *Config) WrapConnServer(conn net.Conn) (net.Conn, error) {
	limiter, err := c.serverAdmission()
	if err != nil {
		return nil, err
	}
	cc, err := wrapConnServer(conn, nil, c.Password, c.CamouflagePublicKey)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}
	// Admission stays outside Accept because RemoteAddr may wait for a PROXY header.
	cc.limiter = limiter
	if err := cc.deadlines.beginHandshake(); err != nil {
		_ = cc.Close()
		return nil, err
	}
	cc.dest, cc.protocolVersion = c.Dest, c.ProtocolVersion
	if c.Dest != "" {
		PrepareDest(c.Dest, c.ProtocolVersion)
	}

	return cc, nil
}
