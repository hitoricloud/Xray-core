package hmc

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"
)

type recordingReader struct {
	conn net.Conn
	bytes.Buffer
	active bool
}

func (r *recordingReader) Read(p []byte) (int, error) {
	n, err := r.conn.Read(p)
	if r.active {
		_, _ = r.Buffer.Write(p[:n])
	}
	return n, err
}

type relayLimits struct {
	idle, total      time.Duration
	upload, download int64
	slots            chan struct{}
}

var fallbackLimits = relayLimits{90 * time.Second, 2 * time.Minute, 1 << 20, 8 << 20, make(chan struct{}, 256)}

func relayDest(client net.Conn, dest string, recorded []byte, limits relayLimits) {
	select {
	case limits.slots <- struct{}{}:
		defer func() { <-limits.slots }()
	default:
		admissionWarnings.reject(time.Now())
		return
	}
	deadline := time.Now().Add(limits.total)
	upstream, err := net.DialTimeout("tcp", dest, min(5*time.Second, limits.total))
	if err != nil {
		return
	}
	defer upstream.Close()
	defer client.Close()
	_ = client.SetDeadline(time.Time{})
	started := time.Now()
	var lastActivity atomic.Int64
	touch := func() {
		now := time.Since(started).Nanoseconds()
		for previous := lastActivity.Load(); previous < now; previous = lastActivity.Load() {
			if lastActivity.CompareAndSwap(previous, now) {
				break
			}
		}
	}
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		timer := time.NewTimer(min(limits.idle, time.Until(deadline)))
		defer timer.Stop()
		for {
			select {
			case <-stop:
				return
			case <-timer.C:
				remaining := min(limits.idle-(time.Since(started)-time.Duration(lastActivity.Load())), time.Until(deadline))
				if remaining <= 0 {
					client.Close()
					upstream.Close()
					return
				}
				timer.Reset(remaining)
			}
		}
	}()
	defer func() { close(stop); <-stopped }()
	if int64(len(recorded)) > limits.upload || writeFull(activityWriter{upstream, touch}, recorded) != nil {
		return
	}
	done := make(chan error, 2)
	go func() { done <- relayCopy(upstream, client, limits.upload-int64(len(recorded)), touch) }()
	go func() { done <- relayCopy(client, upstream, limits.download, touch) }()
	err = <-done
	if !errors.Is(err, io.EOF) {
		client.Close()
		upstream.Close()
	}
	// A clean EOF drains the other half within shared idle and total limits.
	<-done
}

type activityWriter struct {
	io.Writer
	touch func()
}

func (w activityWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n > 0 {
		w.touch()
	}
	return n, err
}

func relayCopy(dst, src net.Conn, remaining int64, touch func()) error {
	buffer := make([]byte, 32*1024)
	for remaining > 0 {
		n, err := src.Read(buffer[:min(int64(len(buffer)), remaining)])
		if n > 0 {
			touch()
			if writeErr := writeFull(activityWriter{dst, touch}, buffer[:n]); writeErr != nil {
				return writeErr
			}
			remaining -= int64(n)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if half, ok := dst.(interface{ CloseWrite() error }); ok {
					_ = half.CloseWrite()
				}
			}
			return err
		}
	}
	return errors.New("HMC relay byte limit")
}
