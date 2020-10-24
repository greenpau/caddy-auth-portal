// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
