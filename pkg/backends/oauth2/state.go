package oauth2

import (
	"fmt"
	"sync"
	"time"
)

type stateManager struct {
	mux    sync.Mutex
	nonces map[string]string
	states map[string]time.Time
	codes  map[string]string
	status map[string]interface{}
}

func newStateManager() *stateManager {
	return &stateManager{
		nonces: make(map[string]string),
		states: make(map[string]time.Time),
		codes:  make(map[string]string),
		status: make(map[string]interface{}),
	}
}

func (sm *stateManager) add(state, nonce string) {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	sm.nonces[state] = nonce
	sm.states[state] = time.Now()
}

func (sm *stateManager) del(state string) {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	delete(sm.nonces, state)
	delete(sm.states, state)
	delete(sm.codes, state)
	delete(sm.status, state)
}

func (sm *stateManager) exists(state string) bool {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	if _, exists := sm.states[state]; exists {
		return true
	}
	return false
}

func (sm *stateManager) validateNonce(state, nonce string) error {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	v, exists := sm.nonces[state]
	if !exists {
		return fmt.Errorf("no nonce found for %s", state)
	}
	if v != nonce {
		return fmt.Errorf("nonce mismatch %s (expected) vs. %s (received)", v, nonce)
	}
	return nil
}

func (sm *stateManager) addCode(state, code string) {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	sm.codes[state] = code
}

func manageStateManager(sm *stateManager) {
	intervals := time.NewTicker(time.Minute * time.Duration(2))
	for range intervals.C {
		if sm.states == nil {
			return
		}
		now := time.Now()
		sm.mux.Lock()
		for state, ts := range sm.states {
			deleteState := false
			if _, exists := sm.status[state]; !exists {
				if ts.Sub(now).Minutes() > 5 {
					deleteState = true
				}
			} else {
				if ts.Sub(now).Hours() > 12 {
					deleteState = true
				}
			}
			if deleteState {
				delete(sm.nonces, state)
				delete(sm.states, state)
				delete(sm.codes, state)
				delete(sm.status, state)
			}
		}
		sm.mux.Unlock()
	}
	return
}
