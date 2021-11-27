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

package cache

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/greenpau/caddy-auth-portal/pkg/errors"
)

// Memory is a state store that stores state in memory on the current process.
type Memory struct {
	mux    sync.Mutex
	keys   map[string][]byte // Serialize with json to avoid mutations and make it easier to write to interface{}
	timers map[string]time.Time
}

// NewMemoryCache creates a new in memory cache.
func NewMemoryCache() *Memory {
	return &Memory{
		keys:   make(map[string][]byte),
		timers: make(map[string]time.Time),
	}
}

// Add a new key to the store.
func (sm *Memory) Add(key string, value interface{}) error {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	marshaledValue, err := json.Marshal(value)
	if err != nil {
		return errors.ErrCache.WithArgs("add", fmt.Errorf("failed to add key %s %w", key, err))
	}
	sm.keys[key] = marshaledValue
	sm.timers[key] = time.Now()
	return nil
}

// Get gets a value from the cache already casted to your type.
func (sm *Memory) Get(key string, output interface{}) error {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	value, exists := sm.keys[key]
	if !exists {
		return errors.ErrCache.WithArgs("get", fmt.Errorf("failed to find %s in the cache", key))
	}
	if err := json.Unmarshal(value, output); err != nil {
		return errors.ErrCache.WithArgs("get", fmt.Errorf("failed to unmarshal %s %w", key, err))
	}
	return nil
}

// Del deletes a state from the store.
func (sm *Memory) Del(key string) error {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	delete(sm.keys, key)
	delete(sm.timers, key)
	return nil
}

// Exists checks if a state exists in the store.
func (sm *Memory) Exists(key string) (bool, error) {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	if _, exists := sm.timers[key]; exists {
		return true, nil
	}
	return false, nil
}

// Init initializes a memory cleanup routine.
func (sm *Memory) Init() error {
	go func() {
		intervals := time.NewTicker(time.Minute * time.Duration(2))
		for range intervals.C {
			if sm.timers == nil {
				return
			}
			now := time.Now()
			sm.mux.Lock()
			for key, ts := range sm.timers {
				deleteState := false
				if _, exists := sm.timers[key]; !exists {
					if ts.Sub(now).Minutes() > 5 {
						deleteState = true
					}
				} else {
					if ts.Sub(now).Hours() > 12 {
						deleteState = true
					}
				}
				if deleteState {
					delete(sm.keys, key)
					delete(sm.timers, key)
				}
			}
			sm.mux.Unlock()
		}
	}()
	return nil
}

func (sm *Memory) String() string {
	return string(MemoryBackend)
}
