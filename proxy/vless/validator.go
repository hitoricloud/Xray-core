package vless

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

type Validator interface {
	Get(id uuid.UUID) *protocol.MemoryUser
	Add(u *protocol.MemoryUser) error
	Del(email string) error
	GetByEmail(email string) *protocol.MemoryUser
	GetAll() []*protocol.MemoryUser
	GetCount() int64
}

func ProcessUUID(id [16]byte) [16]byte {
	id[6] = 0
	id[7] = 0
	return id
}

// MemoryValidator stores valid VLESS users.
// Using native maps + RWMutex is faster than sync.Map for the typical static
// user sets on a production server.
type MemoryValidator struct {
	mu     sync.RWMutex
	email  map[string]*protocol.MemoryUser
	users  map[[16]byte]*protocol.MemoryUser
	count  atomic.Int64
}

// NewMemoryValidator creates a new MemoryValidator.
func NewMemoryValidator() *MemoryValidator {
	return &MemoryValidator{
		email: make(map[string]*protocol.MemoryUser),
		users: make(map[[16]byte]*protocol.MemoryUser),
	}
}

// Add a VLESS user, Email must be empty or unique.
func (v *MemoryValidator) Add(u *protocol.MemoryUser) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if u.Email != "" {
		le := strings.ToLower(u.Email)
		if _, loaded := v.email[le]; loaded {
			return errors.New("User ", u.Email, " already exists.")
		}
		v.email[le] = u
	}
	v.users[ProcessUUID(u.Account.(*MemoryAccount).ID.UUID())] = u
	v.count.Add(1)
	return nil
}

// Del a VLESS user with a non-empty Email.
func (v *MemoryValidator) Del(e string) error {
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
	delete(v.users, ProcessUUID(u.Account.(*MemoryAccount).ID.UUID()))
	v.count.Add(-1)
	return nil
}

// Get a VLESS user with UUID, nil if user doesn't exist.
func (v *MemoryValidator) Get(id uuid.UUID) *protocol.MemoryUser {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.users[ProcessUUID(id)]
}

// Get a VLESS user with email, nil if user doesn't exist.
func (v *MemoryValidator) GetByEmail(email string) *protocol.MemoryUser {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.email[strings.ToLower(email)]
}

// Get all users
func (v *MemoryValidator) GetAll() []*protocol.MemoryUser {
	v.mu.RLock()
	defer v.mu.RUnlock()

	u := make([]*protocol.MemoryUser, 0, len(v.email))
	for _, value := range v.email {
		u = append(u, value)
	}
	return u
}

// Get users count
func (v *MemoryValidator) GetCount() int64 {
	return v.count.Load()
}
