package observatory

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/features/outbound"
)

type emptyTestSelector struct {
	outbound.Manager
	called chan struct{}
}

func (s *emptyTestSelector) Select([]string) []string {
	select {
	case s.called <- struct{}{}:
	default:
	}
	return nil
}

func TestEmptySelectorBacksOffAndStops(t *testing.T) {
	selector := &emptyTestSelector{called: make(chan struct{}, 1)}
	o := &Observer{ctx: context.Background(), config: &Config{SubjectSelector: []string{"TEST"}, ProbeInterval: int64(time.Hour)}, ohm: selector, finished: done.New()}
	stopped := make(chan struct{})
	go func() { o.background(); close(stopped) }()
	t.Cleanup(func() {
		o.Close()
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Error("observer did not stop")
		}
	})
	select {
	case <-selector.called:
	case <-time.After(time.Second):
		t.Fatal("selector was not queried")
	}
	select {
	case <-selector.called:
		t.Fatal("empty selector busy-looped")
	case <-time.After(40 * time.Millisecond):
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("empty selector sleep ignored Close")
	}
}
