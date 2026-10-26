package http

import (
	"bufio"
	"bytes"
	"io"
	stdnet "net"
	stdhttp "net/http"
	"strings"
	"testing"
)

// Regression from upstream 8ee131cb.
func TestShortInterimResponseDoesNotPanic(t *testing.T) {
	payload := "X\nHTTP/1.1 100 Continue\r\n\r\n" + strings.Repeat("A", 40)
	req, err := stdhttp.NewRequest("GET", "http://test.invalid/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = readResponseAndHandle100Continue(bufio.NewReader(strings.NewReader(payload)), req, io.Discard)
}

func TestInterimResponseStillForwards(t *testing.T) {
	payload := "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	req, _ := stdhttp.NewRequest("GET", "http://test.invalid/", nil)
	var forwarded bytes.Buffer
	resp, err := readResponseAndHandle100Continue(bufio.NewReader(strings.NewReader(payload)), req, &forwarded)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !strings.Contains(forwarded.String(), "100 Continue") {
		t.Fatal("interim/final response changed")
	}
	resp.Body.Close()
}

func TestCONNECTReadAheadPreserved(t *testing.T) {
	left, right := stdnet.Pipe()
	defer left.Close()
	defer right.Close()
	conn := &earlyDataConn{Conn: left, early: []byte("hello")}
	first := make([]byte, 2)
	if n, e := conn.Read(first); e != nil || n != 2 || string(first) != "he" {
		t.Fatal("first early chunk lost")
	}
	rest := make([]byte, 3)
	if n, e := conn.Read(rest); e != nil || n != 3 || string(rest) != "llo" {
		t.Fatal("remaining early chunk lost")
	}
	done := make(chan error, 1)
	go func() { _, e := right.Write([]byte("later")); done <- e }()
	actual := make([]byte, 5)
	if _, err := io.ReadFull(conn, actual); err != nil || string(actual) != "later" {
		t.Fatal("underlying stream not resumed")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
