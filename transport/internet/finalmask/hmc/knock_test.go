package hmc

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestKnockIsUniquePerConnectionAndVerifiable(t *testing.T) {
	now := time.Unix(1_800_000_030, 0)
	cache := newReplayCache(1024, time.Minute)
	uuid := testLoginProfile("test_user").UUID
	seen := map[String]bool{}
	for range 200 {
		knock := loginKnock(testPassword, "localhost", "test_user", uuid, now.Unix()/30)
		if seen[knock] {
			t.Fatal("two connections produced the same knock")
		}
		seen[knock] = true
		token := knockToken(knock)
		if len(token) != 18 || len(strings.Split(string(knock), "\x00")[1]) != 24 {
			t.Fatal("invalid suffix shape")
		}
		if !validKnock(testPassword, knock, "test_user", uuid, now) || !cache.firstUse(token, now) {
			t.Fatal("parallel connections sharing profile and window must all be accepted")
		}
		if cache.firstUse(token, now) {
			t.Fatal("replayed token accepted")
		}
	}
}

func TestKnockFormula(t *testing.T) {
	uuid, nonce := testLoginProfile("test_user").UUID, []byte{0, 1, 2, 3, 4, 5, 6, 7}
	host, name, window := String("dest.example"), String("test_user"), fallbackTime.Unix()/30
	mac := hmac.New(sha256.New, passwordSecret(testPassword))
	mac.Write([]byte("hmc1 knock"))
	mac.Write(binary.BigEndian.AppendUint64(nil, uint64(window)))
	for _, value := range []String{host, name} {
		mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(value))))
		mac.Write([]byte(value))
	}
	mac.Write(uuid[:])
	mac.Write(nonce)
	expected := append(append([]byte(nil), nonce...), mac.Sum(nil)[:10]...)
	address := host + "\x00" + String(base64.RawURLEncoding.EncodeToString(expected))
	if !bytes.Equal(knockTag(testPassword, host, name, uuid, window, nonce), expected[8:]) || !validKnock(testPassword, address, name, uuid, fallbackTime) {
		t.Fatal("knock differs from specified transcript")
	}
}

type knockAttempt struct {
	server        *serverConn
	raw           net.Conn
	done          <-chan error
	secret, proof Bytes
	token         Bytes
	keys          *sessionKeys
}

func beginKnockAttempt(t *testing.T, dest string, cache *replayCache, knock String) *knockAttempt {
	t.Helper()
	raw, _, done := fallbackPair(t, dest, cache, nil)
	uuid := testLoginProfile("test_user").UUID
	if err := writeFull(raw, loginStartWire(t, knock, 2, uuid)); err != nil {
		t.Fatal(err)
	}
	request, err := readPacket(raw)
	if err != nil || request.packetID != 1 {
		t.Fatalf("MAC-valid knock must get Encryption Request: %v", err)
	}
	var id String
	var key, token Bytes
	if err := request.readFields(&id, &key, &token); err != nil {
		t.Fatal(err)
	}
	binding := loginBinding(775, knock, 25565, "test_user", uuid, id, key, token)
	secret, proof, keys, err := newLoginResponse(testPassword, binding, token, key)
	if err != nil {
		t.Fatal(err)
	}
	return &knockAttempt{raw: raw, done: done, secret: secret, proof: proof, keys: keys, token: token}
}

func (a *knockAttempt) finish(t *testing.T) bool {
	t.Helper()
	var wire bytes.Buffer
	if err := writePacket(&wire, 1, &a.secret, &a.proof); err != nil {
		t.Fatal(err)
	}
	writer, err := newCryptoWriter(&wire, a.keys.clientToServer)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePacket(writer, 3); err != nil {
		t.Fatal(err)
	}
	if err := writeFull(a.raw, wire.Bytes()); err != nil {
		t.Fatal(err)
	}
	reader, err := newCryptoReader(a.raw, a.keys.serverToClient)
	if err != nil {
		t.Fatal(err)
	}
	response, err := readPacket(reader)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if err == nil {
		profile, parseErr := readLoginSuccess(response)
		if parseErr != nil || profile != testLoginProfile("test_user") {
			t.Fatalf("echo profile=%+v error=%v", profile, parseErr)
		}
		var count Varint
		var name String
		var uuid UUID
		if parseErr := response.readFields(&uuid, &name, &count); parseErr != nil || count != 0 {
			t.Fatalf("server sent properties: %v", parseErr)
		}
	}
	serverErr := <-a.done
	a.raw.Close()
	if (err == nil) != (serverErr == nil) {
		t.Fatalf("client=%v server=%v", err, serverErr)
	}
	return err == nil
}

func TestKnockConcurrentProofsOnlyFirstWins(t *testing.T) {
	cache := newReplayCache(16, time.Minute)
	knock := loginKnock(testPassword, "localhost", "test_user", testLoginProfile("test_user").UUID, fallbackTime.Unix()/30)
	a := beginKnockAttempt(t, "", cache, knock)
	b := beginKnockAttempt(t, "", cache, knock)
	if bytes.Equal(a.token, b.token) {
		t.Fatal("concurrent attempts shared a verify token")
	}
	results := make(chan bool, 2)
	go func() { results <- a.finish(t) }()
	go func() { results <- b.finish(t) }()
	first, second := <-results, <-results
	if first == second {
		t.Fatalf("want one success: %v %v", first, second)
	}
}

func TestKnockRejectsForgeryAndWrongContext(t *testing.T) {
	now := fallbackTime
	uuid := testLoginProfile("test_user").UUID
	knock := loginKnock(testPassword, "localhost", "test_user", uuid, now.Unix()/30)
	token := knockToken(knock)
	for bit := 0; bit < 144; bit++ {
		mutated := bytes.Clone(token)
		mutated[bit/8] ^= 1 << (bit % 8)
		address := String("localhost\x00" + base64.RawURLEncoding.EncodeToString(mutated))
		if validKnock(testPassword, address, "test_user", uuid, now) {
			t.Fatalf("flipping bit %d still verifies", bit)
		}
	}
	other := uuid
	other[0] ^= 1
	for name, ok := range map[string]bool{
		"password": validKnock(testPassword+"x", knock, "test_user", uuid, now),
		"host":     validKnock(testPassword, String("other")+knock[len("localhost"):], "test_user", uuid, now),
		"username": validKnock(testPassword, knock, "other_user", uuid, now),
		"uuid":     validKnock(testPassword, knock, "test_user", other, now),
		"stale":    validKnock(testPassword, knock, "test_user", uuid, now.Add(61*time.Second)),
	} {
		if ok {
			t.Fatalf("wrong %s accepted", name)
		}
	}
	for _, name := range []String{"", "ab", "abcdefghijklmnopq", "bad!name", "user\x00name", "юзер"} {
		address := loginKnock(testPassword, "localhost", name, uuid, now.Unix()/30)
		if validKnock(testPassword, address, name, uuid, now) {
			t.Fatalf("invalid username %q accepted", name)
		}
	}
}

func TestKnockSuffixParsingAndFallback(t *testing.T) {
	uuid := testLoginProfile("test_user").UUID
	valid := loginKnock(testPassword, "localhost", "test_user", uuid, fallbackTime.Unix()/30)
	token := strings.Split(string(valid), "\x00")[1]
	cases := []String{"localhost", "localhost\x00", "localhost\x00!" + String(token[1:]), "localhost\x00" + String(token[:23]), "localhost\x00" + String(token) + "=", valid + "\x00more", "localhost\x00\x00" + String(token), "localhost\x00" + String(base64.RawURLEncoding.EncodeToString(make([]byte, 17))), "localhost\x00" + String(base64.RawURLEncoding.EncodeToString(make([]byte, 19)))}
	for _, address := range cases {
		t.Run(string(address), func(t *testing.T) {
			if validKnock(testPassword, address, "test_user", uuid, fallbackTime) {
				t.Fatal("bad suffix accepted")
			}
			wire := loginStartWire(t, address, 2, uuid)
			fake := newFakeDest(t, func(conn net.Conn, reader io.Reader) {
				got := make([]byte, len(wire))
				if _, err := io.ReadFull(reader, got); err == nil {
					_ = writeFull(conn, []byte("fallback"))
				}
			})
			raw, server, done := fallbackPair(t, fake.address(), newReplayCache(16, time.Minute), nil)
			if err := writeFull(raw, wire); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(raw)
			raw.Close()
			<-done
			if err != nil || string(got) != "fallback" {
				t.Fatalf("fallback=%q %v", got, err)
			}
			records := fake.snapshots()
			if len(records) != 1 || !bytes.Equal(records[0], wire) || len(server.knocks.seen) != 0 {
				t.Fatal("fallback changed bytes or consumed knock")
			}
		})
	}
}
