package dispatcher

import (
	"context"
	"testing"

	apppolicy "github.com/xtls/xray-core/app/policy"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

func TestDispatcherStatsReregister(t *testing.T) {
	manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := apppolicy.New(context.Background(), &apppolicy.Config{Level: map[uint32]*apppolicy.Policy{0: {Stats: &apppolicy.Policy_Stats{UserUplink: true, UserDownlink: true, UserOnline: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	d := &DefaultDispatcher{stats: manager, policy: policy}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{User: &protocol.MemoryUser{Email: "TEST"}, Source: net.TCPDestination(net.ParseAddress("192.0.2.1"), 1234)})
	for i := 0; i < 2; i++ {
		linkCtx, cancel := context.WithCancel(ctx)
		in, out := d.getLink(linkCtx)
		for direction, writer := range map[string]*SizeStatWriter{"uplink": in.Writer.(*SizeStatWriter), "downlink": out.Writer.(*SizeStatWriter)} {
			name := "user>>>TEST>>>traffic>>>" + direction
			if counter := manager.GetCounter(name); counter == nil || writer.Counter != counter {
				t.Errorf("%s link uses an unregistered or stale counter", direction)
			}
			if err := manager.UnregisterCounter(name); err != nil {
				t.Fatal(err)
			}
		}
		if online := manager.GetOnlineMap("user>>>TEST>>>online"); online == nil || online.Count() != 1 {
			t.Error("link uses an unregistered or stale online map")
		}
		if err := manager.UnregisterOnlineMap("user>>>TEST>>>online"); err != nil {
			t.Fatal(err)
		}
		cancel()
		common.Interrupt(in.Reader)
		common.Interrupt(out.Reader)
		common.Close(in.Writer)
		common.Close(out.Writer)
	}
}
