package uuid // import "github.com/xtls/xray-core/common/uuid"

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
)

var byteGroups = []int{8, 4, 4, 4, 12}

type UUID [16]byte

// String returns the string representation of this UUID.
func (u *UUID) String() string {
	bytes := u.Bytes()
	result := [36]byte{}
	i := 0
	offset := 0
	for _, group := range byteGroups {
		if i > 0 {
			result[i] = '-'
			i++
		}
		hex.Encode(result[i:i+group], bytes[offset:offset+group/2])
		i += group
		offset += group / 2
	}
	return string(result[:])
}

// Bytes returns the bytes representation of this UUID.
func (u *UUID) Bytes() []byte {
	return u[:]
}

// Equals returns true if this UUID equals another UUID by value.
func (u *UUID) Equals(another *UUID) bool {
	if u == nil && another == nil {
		return true
	}
	if u == nil || another == nil {
		return false
	}
	return bytes.Equal(u.Bytes(), another.Bytes())
}

// New creates a UUID with random value.
func New() UUID {
	var uuid UUID
	common.Must2(rand.Read(uuid.Bytes()))
	uuid[6] = (uuid[6] & 0x0f) | (4 << 4)
	uuid[8] = (uuid[8]&(0xff>>2) | (0x02 << 6))
	return uuid
}

// ParseBytes converts a UUID in byte form to object.
func ParseBytes(b []byte) (UUID, error) {
	var uuid UUID
	if len(b) != 16 {
		return uuid, errors.New("invalid UUID: ", b)
	}
	copy(uuid[:], b)
	return uuid, nil
}

// ParseString converts a UUID in string form to object.
func ParseString(str string) (UUID, error) {
	var uuid UUID

	text := []byte(str)
	if l := len(text); l < 32 || l > 36 {
		if l == 0 || l > 30 {
			return uuid, errors.New("invalid UUID: ", str)
		}
		h := sha1.New()
		h.Write(uuid[:])
		h.Write(text)
		u := h.Sum(nil)[:16]
		u[6] = (u[6] & 0x0f) | (5 << 4)
		u[8] = (u[8]&(0xff>>2) | (0x02 << 6))
		copy(uuid[:], u)
		return uuid, nil
	}

	b := uuid.Bytes()

	for _, byteGroup := range byteGroups {
		if len(text) > 0 && text[0] == '-' {
			text = text[1:]
		}

		if len(text) < byteGroup {
			return uuid, errors.New("invalid UUID: ", str)
		}

		if _, err := hex.Decode(b[:byteGroup/2], text[:byteGroup]); err != nil {
			return uuid, err
		}

		text = text[byteGroup:]
		b = b[byteGroup/2:]
	}

	return uuid, nil
}
