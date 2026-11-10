package stats_test

import (
	"context"
	"sync"
	"testing"

	appstats "github.com/xtls/xray-core/app/stats"
)

func TestAtomicGetOrRegister(t *testing.T) {
	m, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	cases := map[string]func() (any, error){
		"counter": func() (any, error) { return m.GetOrRegisterCounter("TEST") },
		"online":  func() (any, error) { return m.GetOrRegisterOnlineMap("TEST") },
		"channel": func() (any, error) { return m.GetOrRegisterChannel("TEST") },
	}
	for name, get := range cases {
		t.Run(name, func(t *testing.T) {
			type result struct {
				value any
				err   error
			}
			results := make(chan result, 16)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := 0; i < 16; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); <-start; v, e := get(); results <- result{v, e} }()
			}
			close(start)
			wg.Wait()
			close(results)
			var first any
			for r := range results {
				if r.err != nil {
					t.Error(r.err)
					continue
				}
				if r.value == nil {
					t.Error("nil registration")
					continue
				}
				if first == nil {
					first = r.value
				} else if first != r.value {
					t.Error("concurrent calls returned different registered objects")
				}
			}
		})
	}
}
