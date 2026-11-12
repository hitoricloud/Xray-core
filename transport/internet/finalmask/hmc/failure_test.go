package hmc

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

type testTimeout struct{}

func (testTimeout) Error() string   { return "injected timeout" }
func (testTimeout) Timeout() bool   { return true }
func (testTimeout) Temporary() bool { return true }

type interruptedFrame struct {
	head, tail *bytes.Reader
	failed     bool
	calls      int
}

func (r *interruptedFrame) Read(p []byte) (int, error) {
	r.calls++
	if r.head.Len() > 0 {
		return r.head.Read(p)
	}
	if !r.failed {
		r.failed = true
		return 0, testTimeout{}
	}
	return r.tail.Read(p)
}

type partialFailureWriter struct{ calls int }

func (w *partialFailureWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == 1 {
		return min(1, len(p)), testTimeout{}
	}
	return len(p), nil
}

func TestPacketStreamEOFAndTruncation(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire []byte
		want error
	}{
		{name: "boundary", want: io.EOF},
		{name: "partial prefix", wire: []byte{0x80}, want: io.ErrUnexpectedEOF},
		{name: "partial body", wire: []byte{3, 1}, want: io.ErrUnexpectedEOF},
		{name: "missing body", wire: []byte{3}, want: io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := newPacketStream(bytes.NewReader(tc.wire), io.Discard, true)
			_, first := stream.Read(make([]byte, 1))
			if !errors.Is(first, tc.want) {
				t.Fatalf("got %v, want %v", first, tc.want)
			}
			if tc.want == io.EOF && first != io.EOF {
				t.Fatalf("boundary EOF must be bare io.EOF, got %v", first)
			}
			if _, again := stream.Read(make([]byte, 1)); again != first {
				t.Fatalf("read error changed: %v -> %v", first, again)
			}
		})
	}
}

func TestPacketStreamPartialReadErrorIsPermanent(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		var frame bytes.Buffer
		channel, payload := String(packetChannel), RestBytes("data")
		if err := writePacket(&frame, configurationClientboundCustomPayload, &channel, &payload); err != nil {
			t.Fatal(err)
		}
		wire := frame.Bytes()
		key := streamKey{0x42}
		if encrypted {
			var encoded bytes.Buffer
			writer, err := newCryptoWriter(&encoded, key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(wire); err != nil {
				t.Fatal(err)
			}
			wire = encoded.Bytes()
		}
		input := &interruptedFrame{head: bytes.NewReader(wire[:2]), tail: bytes.NewReader(wire[2:])}
		var reader io.Reader = input
		if encrypted {
			var err error
			reader, err = newCryptoReader(input, key)
			if err != nil {
				t.Fatal(err)
			}
		}
		stream := newPacketStream(reader, io.Discard, true)
		_, first := stream.Read(make([]byte, 1))
		if timeout, ok := first.(net.Error); !ok || !timeout.Timeout() {
			t.Fatalf("expected direct net.Error timeout, got %T: %v", first, first)
		}
		calls := input.calls
		if _, again := stream.Read(make([]byte, 1)); again != first || input.calls != calls {
			t.Fatalf("retried a partially consumed frame: err=%v calls=%d -> %d", again, calls, input.calls)
		}
	}
}

func TestPacketStreamBoundaryTimeoutIsRecoverable(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		var frame bytes.Buffer
		channel, payload := String(packetChannel), RestBytes("data")
		if err := writePacket(&frame, configurationClientboundCustomPayload, &channel, &payload); err != nil {
			t.Fatal(err)
		}
		wire, key := frame.Bytes(), streamKey{0x42}
		if encrypted {
			var encoded bytes.Buffer
			writer, err := newCryptoWriter(&encoded, key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(wire); err != nil {
				t.Fatal(err)
			}
			wire = encoded.Bytes()
		}
		var reader io.Reader = &interruptedFrame{head: bytes.NewReader(nil), tail: bytes.NewReader(wire)}
		if encrypted {
			var err error
			if reader, err = newCryptoReader(reader, key); err != nil {
				t.Fatal(err)
			}
		}
		stream := newPacketStream(reader, io.Discard, true)
		if _, err := stream.Read(make([]byte, 4)); err == nil {
			t.Fatal("expected clean-boundary timeout")
		} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatalf("expected direct timeout, got %T: %v", err, err)
		}
		got := make([]byte, 4)
		if _, err := io.ReadFull(stream, got); err != nil || string(got) != "data" {
			t.Fatalf("stream did not recover after boundary timeout: %q, %v", got, err)
		}
	}
}

func TestPacketAndCryptoWriteErrorsArePermanent(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		output := &partialFailureWriter{}
		var writer io.Writer = output
		if encrypted {
			var err error
			writer, err = newCryptoWriter(output, streamKey{0x42})
			if err != nil {
				t.Fatal(err)
			}
		}
		stream := newPacketStream(bytes.NewReader(nil), writer, true)
		_, first := stream.Write([]byte("first"))
		if timeout, ok := first.(net.Error); !ok || !timeout.Timeout() {
			t.Fatalf("expected direct net.Error timeout, got %T: %v", first, first)
		}
		if _, again := stream.Write([]byte("retry")); again != first {
			t.Fatalf("write error changed: %v -> %v", first, again)
		}
		if again := stream.writeKeepAlive(1); again != first || output.calls != 1 {
			t.Fatalf("wrote after partial frame: error=%v calls=%d", again, output.calls)
		}
		if encrypted {
			if _, again := writer.Write([]byte("direct crypto retry")); again != first || output.calls != 1 {
				t.Fatalf("reused advanced cipher after failure: error=%v calls=%d", again, output.calls)
			}
		}
	}
}
