package policy

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/features/policy"
)

// Instance is an instance of Policy manager.
type Instance struct {
	levels map[uint32]*Policy
	system *SystemPolicy
	// cache stores the converted policy.Session for each level to avoid
	// rebuilding the struct on every hot-path lookup.
	cache map[uint32]policy.Session
}

// New creates new Policy manager instance.
func New(ctx context.Context, config *Config) (*Instance, error) {
	m := &Instance{
		levels: make(map[uint32]*Policy),
		cache:  make(map[uint32]policy.Session),
		system: config.System,
	}
	if len(config.Level) > 0 {
		for lv, p := range config.Level {
			pp := defaultPolicy()
			pp.overrideWith(p)
			m.levels[lv] = pp
			m.cache[lv] = pp.ToCorePolicy()
		}
	}

	return m, nil
}

// Type implements common.HasType.
func (*Instance) Type() interface{} {
	return policy.ManagerType()
}

// ForLevel implements policy.Manager.
func (m *Instance) ForLevel(level uint32) policy.Session {
	if p, ok := m.cache[level]; ok {
		return p
	}
	return policy.SessionDefault()
}

// ForSystem implements policy.Manager.
func (m *Instance) ForSystem() policy.System {
	if m.system == nil {
		return policy.System{}
	}
	return m.system.ToCorePolicy()
}

// Start implements common.Runnable.Start().
func (m *Instance) Start() error {
	return nil
}

// Close implements common.Closable.Close().
func (m *Instance) Close() error {
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
