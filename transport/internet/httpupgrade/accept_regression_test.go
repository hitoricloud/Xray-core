package httpupgrade

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type testAcceptListener struct{ calls int }

func (l *testAcceptListener) Accept() (net.Conn, error) {
	l.calls++
	if l.calls == 1 {
		return nil, errors.New("temporary TEST accept failure")
	}
	return nil, net.ErrClosed
}
func (*testAcceptListener) Close() error   { return nil }
func (*testAcceptListener) Addr() net.Addr { return nil }

func TestAcceptContinuesAfterTransientFailure(t *testing.T) {
	listener := &testAcceptListener{}
	s := &server{innnerListener: listener}
	stopped := make(chan struct{})
	go func() { s.keepAccepting(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("accept loop did not stop on closed listener")
	}
	if listener.calls != 2 {
		t.Fatalf("transient failure stopped listener after %d accept calls", listener.calls)
	}
}

type testDeadlineConn struct {
	net.Conn
	deadlines []time.Time
}

func (*testDeadlineConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *testDeadlineConn) SetReadDeadline(v time.Time) error {
	c.deadlines = append(c.deadlines, v)
	return nil
}

func TestUpgradeBoundsHandshakeRead(t *testing.T) {
	c := &testDeadlineConn{}
	before := time.Now()
	if _, err := (&server{}).upgrade(c); err == nil {
		t.Fatal("empty request unexpectedly upgraded")
	}
	if len(c.deadlines) != 2 || c.deadlines[0].Before(before.Add(3*time.Second)) || !c.deadlines[1].IsZero() {
		t.Fatal("handshake deadline missing or not cleared")
	}
}
