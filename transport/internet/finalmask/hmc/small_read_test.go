package hmc

import (
	"bytes"
	"io"
	"testing"
)

func smallReadRun(t *testing.T, frames int) func() {
	payload := make([]byte, maxPacketData)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	var wire bytes.Buffer
	writer := newPacketStream(bytes.NewReader(nil), &wire, false)
	for i := 0; i < frames; i++ {
		if _, err := writer.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	writer.Stop()
	encoded := wire.Bytes()

	return func() {
		stream := newPacketStream(bytes.NewReader(encoded), io.Discard, true)
		defer stream.Stop()
		got := make([]byte, len(payload))
		for frame := 0; frame < frames; frame++ {
			for off := 0; off < len(got); {
				n, err := stream.Read(got[off:min(off+5, len(got))])
				if err != nil {
					t.Fatal(err)
				}
				off += n
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("frame %d corrupted by small reads", frame)
			}
		}
	}
}

// Callers such as VLESS Encryption read headers and bodies in small pieces. The
// old pending copy reallocated once per frame; measure the cost of extra frames
// so fixed per-run overhead (and race-detector noise) cancels out.
func TestPacketStreamSmallReadsKeepDataAndDoNotAllocatePerFrame(t *testing.T) {
	few, many := smallReadRun(t, 40), smallReadRun(t, 80)
	few()
	many()
	extra := testing.AllocsPerRun(5, many) - testing.AllocsPerRun(5, few)
	if extra > 8 {
		t.Fatalf("40 additional frames cost %v extra allocations", extra)
	}
}
