package errors

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/log"
)

type discardHandler struct{}

func (discardHandler) Handle(log.Message) {}

func BenchmarkLogInfo(b *testing.B) {
	log.RegisterHandler(discardHandler{})
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		LogInfo(ctx, "received request for ", i, " ", "some destination")
	}
}

func BenchmarkLogDebug(b *testing.B) {
	log.RegisterHandler(discardHandler{})
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		LogDebug(ctx, "debug message ", i)
	}
}

func BenchmarkLogInfoSkipped(b *testing.B) {
	log.RegisterHandler(discardHandler{})
	log.SetMinSeverity(log.Severity_Warning)
	defer log.SetMinSeverity(log.Severity_Debug)

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		LogInfo(ctx, "received request for ", i, " ", "some destination")
	}
}
