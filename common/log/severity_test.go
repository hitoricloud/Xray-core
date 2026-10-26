package log_test

import (
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/log"
)

// These tests change a process-wide threshold and must not run in parallel.
func TestSeverityDefault(t *testing.T) {
	if !log.IsSeverityEnabled(log.Severity_Debug) {
		t.Fatal("the default threshold must enable debug messages")
	}
}

func TestSeverityThreshold(t *testing.T) {
	t.Cleanup(func() { log.SetMinSeverity(log.Severity_Debug) })
	levels := []log.Severity{
		log.Severity_Unknown,
		log.Severity_Error,
		log.Severity_Warning,
		log.Severity_Info,
		log.Severity_Debug,
	}
	for _, threshold := range levels {
		t.Run(threshold.String(), func(t *testing.T) {
			log.SetMinSeverity(threshold)
			for _, level := range levels {
				if got, want := log.IsSeverityEnabled(level), level <= threshold; got != want {
					t.Errorf("threshold %s, level %s: enabled=%t, want %t", threshold, level, got, want)
				}
			}
		})
	}
}

func TestSeverityConcurrent(t *testing.T) {
	t.Cleanup(func() { log.SetMinSeverity(log.Severity_Debug) })
	log.SetMinSeverity(log.Severity_Warning)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			log.SetMinSeverity(log.Severity_Warning)
			log.SetMinSeverity(log.Severity_Debug)
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			if !log.IsSeverityEnabled(log.Severity_Error) {
				t.Error("both thresholds must enable errors")
			}
			_ = log.IsSeverityEnabled(log.Severity_Debug)
		}
	}()
	close(start)
	wg.Wait()
}
