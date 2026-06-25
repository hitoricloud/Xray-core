package dispatcher

import (
	"testing"

	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/log"
)

type discardHandler struct{}

func (discardHandler) Handle(log.Message) {}

func BenchmarkGetOrRegisterUplinkCounter(b *testing.B) {
	log.RegisterHandler(discardHandler{})
	manager, err := appstats.NewManager(nil, &appstats.Config{})
	if err != nil {
		b.Fatal(err)
	}
	d := &DefaultDispatcher{stats: manager}

	// Pre-register one counter so the benchmark measures the cached path.
	_ = d.getOrRegisterCounter(&d.uplinkCounters, "user@example.com", "uplink")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.getOrRegisterCounter(&d.uplinkCounters, "user@example.com", "uplink")
	}
}

func BenchmarkGetOrRegisterUplinkCounterUncached(b *testing.B) {
	log.RegisterHandler(discardHandler{})
	manager, err := appstats.NewManager(nil, &appstats.Config{})
	if err != nil {
		b.Fatal(err)
	}
	d := &DefaultDispatcher{stats: manager}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.getOrRegisterCounter(&d.uplinkCounters, "user" + string(rune('0'+i%10)) + "@example.com", "uplink")
	}
}
