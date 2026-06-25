package policy

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/features/policy"
)

func BenchmarkForLevel(b *testing.B) {
	config := &Config{
		Level: map[uint32]*Policy{
			0: {
				Timeout: &Policy_Timeout{
					Handshake:      &Second{Value: 60},
					ConnectionIdle: &Second{Value: 300},
					UplinkOnly:     &Second{Value: 1},
					DownlinkOnly:   &Second{Value: 1},
				},
				Buffer: &Policy_Buffer{Connection: 512 * 1024},
			},
			1: {
				Timeout: &Policy_Timeout{
					Handshake:      &Second{Value: 30},
					ConnectionIdle: &Second{Value: 150},
				},
				Buffer: &Policy_Buffer{Connection: 256 * 1024},
			},
		},
	}
	m, err := New(context.Background(), config)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.ForLevel(uint32(i % 3))
	}
	_ = policy.SessionDefault()
}
