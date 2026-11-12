package hmc

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	// Invalid SPKI uses the legacy RSA-1024-shaped fields.
	fieldLength  = 128
	tokenLength  = 4
	cipherKeyLen = 32
	cipherIVLen  = 16
)

var errInvalidLogin = errors.New("invalid encryption response")

func parseRSA(der []byte) *rsa.PublicKey {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok || key.N == nil || key.N.BitLen() < 512 || key.Size() > (maxPacketDataLength-16)/2 || key.E < 3 {
		return nil
	}
	return key
}

func knockTag(password string, host, username String, uuid UUID, window int64, nonce []byte) []byte {
	mac := hmac.New(sha256.New, passwordSecret(password))
	mac.Write([]byte("hmc1 knock"))
	mac.Write(binary.BigEndian.AppendUint64(nil, uint64(window)))
	for _, value := range []String{host, username} {
		mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(value))))
		mac.Write([]byte(value))
	}
	mac.Write(uuid[:])
	mac.Write(nonce)
	return mac.Sum(nil)[:10]
}

func loginKnock(password string, host, username String, uuid UUID, window int64) String {
	var token [18]byte
	_, _ = rand.Read(token[:8])
	copy(token[8:], knockTag(password, host, username, uuid, window, token[:8]))
	return host + "\x00" + String(base64.RawURLEncoding.EncodeToString(token[:]))
}

func knockToken(address String) []byte {
	_, encoded, found := strings.Cut(string(address), "\x00")
	if !found || len(encoded) != 24 {
		return nil
	}
	token, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(token) != 18 {
		return nil
	}
	return token
}

func validKnock(password string, address, username String, uuid UUID, now time.Time) bool {
	token := knockToken(address)
	if token == nil || !usernamePattern.MatchString(string(username)) {
		return false
	}
	host, _, _ := strings.Cut(string(address), "\x00")
	valid := 0
	for delta := int64(-1); delta <= 1; delta++ {
		valid |= subtle.ConstantTimeCompare(knockTag(password, String(host), username, uuid, now.Unix()/30+delta, token[:8]), token[8:])
	}
	return valid == 1
}

type streamKey [cipherKeyLen + cipherIVLen]byte

type sessionKeys struct {
	clientToServer streamKey
	serverToClient streamKey
}

// Legacy fields have a clear top bit.
func randomField() ([]byte, error) {
	field := make([]byte, fieldLength)
	if _, err := rand.Read(field); err != nil {
		return nil, err
	}
	field[0] &= 0x7f
	return field, nil
}

type stretchedPassword struct {
	once sync.Once
	key  []byte
}

var stretchedPasswords sync.Map

// Stretch once per configured password, never per attacker input.
func passwordSecret(password string) []byte {
	entry, _ := stretchedPasswords.LoadOrStore(password, new(stretchedPassword))
	stretched := entry.(*stretchedPassword)
	stretched.once.Do(func() {
		stretched.key = argon2.IDKey([]byte(password), []byte("hmc1 password"), 2, 32*1024, 2, 32)
		// Hand the 32 MiB Argon2 working set back to the OS instead of keeping it as idle heap.
		go debug.FreeOSMemory()
	})
	return stretched.key
}

// PrepareSecret warms the password secret asynchronously.
func PrepareSecret(password string) {
	go passwordSecret(password)
}

// Binds a login proof to the plaintext packets an on-path attacker could edit.
func loginBinding(version Varint, address String, port UnsignedShort, username String, uuid UUID, serverID String, publicKey, token []byte) []byte {
	h := sha256.New()
	put := func(b []byte) {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(b))))
		h.Write(b)
	}
	put([]byte("hmc1 binding"))
	put(binary.BigEndian.AppendUint32(nil, uint32(version)))
	put([]byte(address))
	put(binary.BigEndian.AppendUint16(nil, uint16(port)))
	put([]byte(username))
	put(uuid[:])
	put([]byte(serverID))
	put(publicKey)
	put(token)
	return h.Sum(nil)
}

func loginProof(password string, publicKey, token, secretField []byte) []byte {
	mac := hmac.New(sha256.New, passwordSecret(password))
	mac.Write([]byte("hmc1 proof"))
	mac.Write(publicKey)
	mac.Write(token)
	mac.Write(secretField)
	return mac.Sum(nil)
}

func deriveSessionKeys(password string, token, secretField []byte) (*sessionKeys, error) {
	salt := append(append([]byte(nil), token...), secretField...)
	keys := new(sessionKeys)
	for info, key := range map[string]*streamKey{"hmc1 c2s": &keys.clientToServer, "hmc1 s2c": &keys.serverToClient} {
		material, err := hkdf.Key(sha256.New, passwordSecret(password), salt, info, len(key))
		if err != nil {
			return nil, err
		}
		copy(key[:], material)
	}
	return keys, nil
}

func newLoginResponse(password string, publicKey, token []byte, publishedKey ...[]byte) (secretField, proofField []byte, keys *sessionKeys, err error) {
	if len(token) != tokenLength || len(publicKey) == 0 {
		return nil, nil, nil, errors.New("bad encryption request")
	}
	var key *rsa.PublicKey
	if len(publishedKey) > 0 {
		key = parseRSA(publishedKey[0])
	}
	if key != nil {
		length := key.Size()
		secret, sampleErr := rand.Int(rand.Reader, key.N)
		if sampleErr != nil {
			return nil, nil, nil, sampleErr
		}
		bound := new(big.Int).Rsh(new(big.Int).Set(key.N), 256)
		prefix, sampleErr := rand.Int(rand.Reader, bound)
		if sampleErr != nil {
			return nil, nil, nil, sampleErr
		}
		secretField = secret.FillBytes(make([]byte, length))
		proofField = new(big.Int).Lsh(prefix, 256).FillBytes(make([]byte, length))
	} else {
		if secretField, err = randomField(); err != nil {
			return nil, nil, nil, err
		}
		if proofField, err = randomField(); err != nil {
			return nil, nil, nil, err
		}
	}
	copy(proofField[len(proofField)-sha256.Size:], loginProof(password, publicKey, token, secretField))
	keys, err = deriveSessionKeys(password, token, secretField)
	return secretField, proofField, keys, err
}

// The response proof is checked before consuming the MAC-valid knock.
func verifyLoginResponse(password string, publicKey, token, secretField, proofField []byte, publishedKey ...[]byte) (*sessionKeys, error) {
	length := fieldLength
	if len(publishedKey) > 0 {
		if key := parseRSA(publishedKey[0]); key != nil {
			length = key.Size()
		}
	}
	expected := loginProof(password, publicKey, token, secretField)
	if len(secretField) != length || len(proofField) != length ||
		subtle.ConstantTimeCompare(proofField[length-sha256.Size:], expected) != 1 {
		return nil, errInvalidLogin
	}
	return deriveSessionKeys(password, token, secretField)
}
