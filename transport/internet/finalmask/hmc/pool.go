package hmc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"sort"
	"sync"
)

type profilePool struct {
	mu       sync.Mutex
	profiles []loginProfile
	leases   []int
}

var profilePools sync.Map

func poolFor(password string, profiles []loginProfile) *profilePool {
	ordered := append([]loginProfile(nil), profiles...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Username != ordered[j].Username {
			return ordered[i].Username < ordered[j].Username
		}
		return string(ordered[i].UUID[:]) < string(ordered[j].UUID[:])
	})
	h := sha256.New()
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(password))))
	h.Write([]byte(password))
	unique := ordered[:0]
	for _, profile := range ordered {
		if len(unique) > 0 && unique[len(unique)-1] == profile {
			continue
		}
		unique = append(unique, profile)
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(profile.Username))))
		h.Write([]byte(profile.Username))
		h.Write(profile.UUID[:])
	}
	key := [32]byte(h.Sum(nil))
	pool, _ := profilePools.LoadOrStore(key, &profilePool{profiles: unique, leases: make([]int, len(unique))})
	return pool.(*profilePool)
}

func (p *profilePool) lease() (loginProfile, func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	free := make([]int, 0, len(p.profiles))
	for i, count := range p.leases {
		if count == 0 {
			free = append(free, i)
		}
	}
	if len(free) == 0 {
		for i := range p.profiles {
			free = append(free, i)
		}
	}
	choice, err := rand.Int(rand.Reader, big.NewInt(int64(len(free))))
	if err != nil {
		return loginProfile{}, nil, err
	}
	i := free[choice.Int64()]
	p.leases[i]++
	var once sync.Once
	return p.profiles[i], func() {
		once.Do(func() {
			p.mu.Lock()
			p.leases[i]--
			p.mu.Unlock()
		})
	}, nil
}
