package errors

import (
	"context"
	stderrors "errors"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/log"
)

type capturedMessages struct{ messages []log.Message }

func (c *capturedMessages) Handle(message log.Message) { c.messages = append(c.messages, message) }

func TestLogEntryThresholds(t *testing.T) {
	recorder := &capturedMessages{}
	log.RegisterHandler(recorder)
	t.Cleanup(func() { log.SetMinSeverity(log.Severity_Debug); log.RegisterHandler(discardHandler{}) })
	ctx := context.Background()
	inner := stderrors.New("TEST inner")
	calls := []struct {
		name  string
		level log.Severity
		call  func()
	}{
		{"debug", log.Severity_Debug, func() { LogDebug(ctx, "TEST") }},
		{"debug-inner", log.Severity_Debug, func() { LogDebugInner(ctx, inner, "TEST") }},
		{"info", log.Severity_Info, func() { LogInfo(ctx, "TEST") }},
		{"info-inner", log.Severity_Info, func() { LogInfoInner(ctx, inner, "TEST") }},
		{"warning", log.Severity_Warning, func() { LogWarning(ctx, "TEST") }},
		{"warning-inner", log.Severity_Warning, func() { LogWarningInner(ctx, inner, "TEST") }},
		{"error", log.Severity_Error, func() { LogError(ctx, "TEST") }},
		{"error-inner", log.Severity_Error, func() { LogErrorInner(ctx, inner, "TEST") }},
	}
	for _, threshold := range []log.Severity{log.Severity_Unknown, log.Severity_Error, log.Severity_Warning, log.Severity_Info, log.Severity_Debug} {
		log.SetMinSeverity(threshold)
		for _, entry := range calls {
			recorder.messages = nil
			entry.call()
			want := 0
			if entry.level <= threshold {
				want = 1
			}
			if len(recorder.messages) != want {
				t.Errorf("threshold %s, %s: got %d messages, want %d", threshold, entry.name, len(recorder.messages), want)
				continue
			}
			if want == 1 {
				message, ok := recorder.messages[0].(*log.GeneralMessage)
				if !ok || message.Severity != entry.level {
					t.Fatal("enabled message severity changed")
				}
				if !strings.Contains(message.String(), "TEST") {
					t.Fatal("enabled message content lost")
				}
				if strings.Contains(entry.name, "inner") && !strings.Contains(message.String(), "TEST inner") {
					t.Fatal("inner error lost")
				}
			}
		}
	}
}
