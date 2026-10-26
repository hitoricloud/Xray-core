package trojan

import (
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// Validator stores valid trojan users.
// Native maps + RWMutex outperform sync.Map for the typical static user sets
// on a production server.
type Validator struct {
	mu    sync.RWMutex
	email map[string]*protocol.MemoryUser
	users map[string]*protocol.MemoryUser
	count atomic.Int64
}

// NewValidator creates a new Validator.
func NewValidator() *Validator {
	return &Validator{
		email: make(map[string]*protocol.MemoryUser),
		users: make(map[string]*protocol.MemoryUser),
	}
}

// Add a trojan user, Email must be empty or unique.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if u.Email != "" {
		le := strings.ToLower(u.Email)
		if _, loaded := v.email[le]; loaded {
			return errors.New("User ", u.Email, " already exists.")
		}
		v.email[le] = u
	}
	key := hex.EncodeToString(u.Account.(*MemoryAccount).Key)
	v.users[key] = u
	v.count.Add(1)
	return nil
}

// Del a trojan user with a non-empty Email.
func (v *Validator) Del(e string) error {
	if e == "" {
		return errors.New("Email must not be empty.")
	}
	le := strings.ToLower(e)

	v.mu.Lock()
	defer v.mu.Unlock()

	u, ok := v.email[le]
	if !ok {
		return errors.New("User ", e, " not found.")
	}
	delete(v.email, le)
	delete(v.users, hex.EncodeToString(u.Account.(*MemoryAccount).Key))
	v.count.Add(-1)
	return nil
}

// Get a trojan user with hashed key, nil if user doesn't exist.
func (v *Validator) Get(hash string) *protocol.MemoryUser {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.users[hash]
}

// GetByKey looks up the 56-byte wire key without allocating an encoded string.
// Keep Get's existing encoded-key API for callers outside the inbound.
func (v *Validator) GetByKey(key []byte) *protocol.MemoryUser {
	const wireKeyLength = 56
	if len(key) != wireKeyLength {
		return nil
	}
	var hash [wireKeyLength * 2]byte
	hex.Encode(hash[:], key)
	v.mu.RLock()
	user := v.users[string(hash[:])]
	v.mu.RUnlock()
	return user
}

// Get a trojan user with hashed key, nil if user doesn't exist.
func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.email[strings.ToLower(email)]
}

// Get all users
func (v *Validator) GetAll() []*protocol.MemoryUser {
	v.mu.RLock()
	defer v.mu.RUnlock()

	u := make([]*protocol.MemoryUser, 0, len(v.email))
	for _, value := range v.email {
		u = append(u, value)
	}
	return u
}

// Get users count
func (v *Validator) GetCount() int64 {
	return v.count.Load()
}
