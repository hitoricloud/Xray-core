// Keyed stream obfuscation for the Minecraft-shaped outer layer.
package hmc

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"sync"
)

// cryptoStream hides the packet stream from passive observers. Integrity and
// confidentiality come from the TLS or VLESS Encryption layer inside it.
type cryptoStream struct {
	stream   cipher.Stream
	r        io.Reader
	w        io.Writer
	mu       sync.Mutex
	scratch  []byte
	out      []byte
	writeErr error
}

func newKeyStream(key streamKey) (cipher.Stream, error) {
	block, err := aes.NewCipher(key[:cipherKeyLen])
	if err != nil {
		return nil, fmt.Errorf("new aes cipher: %w", err)
	}
	return cipher.NewCTR(block, key[cipherKeyLen:]), nil
}

func newCryptoReader(r io.Reader, key streamKey) (*cryptoStream, error) {
	stream, err := newKeyStream(key)
	if err != nil {
		return nil, err
	}
	return &cryptoStream{stream: stream, r: r}, nil
}

func (c *cryptoStream) Read(b []byte) (int, error) {
	if c.r == nil {
		panic("read on a write-only crypto stream")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	size := min(len(b), 32*1024)
	if cap(c.scratch) < size {
		c.scratch = make([]byte, size)
	}
	n, err := c.r.Read(c.scratch[:size])
	if n > 0 {
		c.stream.XORKeyStream(b[:n], c.scratch[:n])
	}
	if err != nil {
		return n, streamError("crypto reader: read", err)
	}

	return n, nil
}

func newCryptoWriter(w io.Writer, key streamKey) (*cryptoStream, error) {
	stream, err := newKeyStream(key)
	if err != nil {
		return nil, err
	}
	return &cryptoStream{stream: stream, w: w}, nil
}

func (c *cryptoStream) Write(b []byte) (int, error) {
	if c.w == nil {
		panic("write on a read-only crypto stream")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}

	if cap(c.out) < len(b) {
		c.out = make([]byte, len(b))
	}
	encrypted := c.out[:len(b)]
	c.stream.XORKeyStream(encrypted, b)

	if err := writeFull(c.w, encrypted); err != nil {
		c.writeErr = streamError("crypto writer: write", err)
		return 0, c.writeErr
	}

	return len(b), nil
}

// A 32 KiB buffer above the cipher turns the per-byte header reads into buffer
// hits and keeps socket reads large; created only after authentication.
func newBufferedCryptoReader(r io.Reader, key streamKey) (io.Reader, error) {
	crypto, err := newCryptoReader(r, key)
	if err != nil {
		return nil, err
	}
	return bufio.NewReaderSize(crypto, 32*1024), nil
}
