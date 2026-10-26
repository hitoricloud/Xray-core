package dns

import (
	"testing"
	"time"

	dnswire "github.com/miekg/dns"
)

func TestResponsePreservesAuthoritativeTTL(t *testing.T) {
	msg := new(dnswire.Msg)
	rr, err := dnswire.NewRR("test.invalid. 7200 IN A 127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	msg.Answer = []dnswire.RR{rr}
	raw, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	record, err := parseResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	ttl := record.Expire.Sub(before)
	if ttl < 7199*time.Second || ttl > 7201*time.Second {
		t.Fatalf("authoritative TTL unexpectedly clamped: %v", ttl)
	}
}
