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
	const name = "user>>>TEST>>>traffic>>>uplink"
	if _, err := manager.GetOrRegisterCounter(name); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = manager.GetOrRegisterCounter(name)
	}
}

func BenchmarkGetOrRegisterTenCounters(b *testing.B) {
	log.RegisterHandler(discardHandler{})
	manager, err := appstats.NewManager(nil, &appstats.Config{})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = manager.GetOrRegisterCounter("user>>>TEST" + string(rune('0'+i%10)) + ">>>traffic>>>uplink")
	}
}
