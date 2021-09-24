// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package state

import (
	"fmt"
	"sync"
	"time"
)

// Memory is a state store that stores state in memory on the current process.
type Memory struct {
	mux    sync.Mutex
	nonces map[string]string
	states map[string]time.Time
	codes  map[string]string
	status map[string]interface{}
}

// NewMemoryState creates a new in memory state store.
func NewMemoryState() *Memory {
	return &Memory{
		nonces: make(map[string]string),
		states: make(map[string]time.Time),
		codes:  make(map[string]string),
		status: make(map[string]interface{}),
	}
}

// Add a new state to the store.
func (sm *Memory) Add(state, nonce string) error {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	sm.nonces[state] = nonce
	sm.states[state] = time.Now()
	return nil
}

// Del deletes a state from the store.
func (sm *Memory) Del(state string) error {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	delete(sm.nonces, state)
	delete(sm.states, state)
	delete(sm.codes, state)
	delete(sm.status, state)
	return nil
}

// Exists checks if a state exists in the store.
func (sm *Memory) Exists(state string) (bool, error) {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	if _, exists := sm.states[state]; exists {
		return true, nil
	}
	return false, nil
}

// ValidateNonce validates the nonce for the give state.
func (sm *Memory) ValidateNonce(state, nonce string) error {
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

// AddCode adds a new code to the store.
func (sm *Memory) AddCode(state, code string) error {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	sm.codes[state] = code
	return nil
}

// Init initializes a memory cleanup routine.
func (sm *Memory) Init() error {
	go func() {
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
	}()
	return nil
}
