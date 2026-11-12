package hmc

import "sync"

var activeKnocks = struct {
	sync.Mutex
	tokens map[[18]byte]int
}{tokens: make(map[[18]byte]int)}

type knockSlot struct {
	token [18]byte
	once  sync.Once
}

func acquireKnockSlot(token []byte) *knockSlot {
	if len(token) != 18 {
		return nil
	}
	key := [18]byte(token)
	activeKnocks.Lock()
	defer activeKnocks.Unlock()
	if activeKnocks.tokens[key] >= 2 {
		return nil
	}
	activeKnocks.tokens[key]++
	return &knockSlot{token: key}
}

func (s *knockSlot) release() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		activeKnocks.Lock()
		defer activeKnocks.Unlock()
		activeKnocks.tokens[s.token]--
		if activeKnocks.tokens[s.token] == 0 {
			delete(activeKnocks.tokens, s.token)
		}
	})
}
