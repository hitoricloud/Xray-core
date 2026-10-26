package buf_test

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

func TestBufferedWriterPartialCapacity(t *testing.T) {
	var output bytes.Buffer
	writer := buf.NewBufferedWriter(buf.NewWriter(&output))
	first := bytes.Repeat([]byte("a"), int(buf.Size)-3)
	second := bytes.Repeat([]byte("b"), int(buf.Size)+17)
	for _, data := range [][]byte{first, second} {
		n, err := writer.Write(data)
		if err != nil || n != len(data) {
			t.Fatalf("write: n=%d, err=%v", n, err)
		}
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), append(first, second...)) {
		t.Fatal("buffered payload changed or truncated")
	}
}
