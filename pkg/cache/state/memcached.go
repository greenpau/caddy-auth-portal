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
	"bytes"
	stdErrors "errors"
	"fmt"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/greenpau/caddy-auth-portal/pkg/errors"
)

const (
	expirationTime = 5 * 60
)

// Memcached implements StateManager interface using memcached as backend.
type Memcached struct {
	client *memcache.Client
}

// NewMemcachedState creates a new state manager using the specified servers.
func NewMemcachedState(server ...string) *Memcached {
	return &Memcached{
		client: memcache.New(server...),
	}
}

// Add a state and its nonce to the backend.
func (sm *Memcached) Add(state, nonce string) error {
	err := sm.client.Set(&memcache.Item{
		Key:        sm.getStateKey(state),
		Value:      []byte(nonce),
		Expiration: expirationTime,
	})
	if err != nil {
		return errors.ErrBackendOauthAddStateFailed.WithArgs(err)
	}
	return nil
}

func (sm *Memcached) getStateKey(state string) string {
	return fmt.Sprintf("auth-portal-state-%s", state)
}

// Del deletes a state from the backend.
func (sm *Memcached) Del(state string) error {
	return sm.client.Delete(sm.getStateKey(state))
}

// Exists checks if the state exists in the backend.
func (sm *Memcached) Exists(state string) (bool, error) {
	_, err := sm.client.Get(sm.getStateKey(state))
	if err == nil {
		return true, nil
	}
	if stdErrors.Is(err, memcache.ErrCacheMiss) {
		return false, nil
	}
	return false, err
}

// ValidateNonce validate a nonce for the give state.
func (sm *Memcached) ValidateNonce(state, nonce string) error {
	storedState, err := sm.client.Get(sm.getStateKey(state))
	if stdErrors.Is(err, memcache.ErrCacheMiss) {
		return fmt.Errorf("no nonce found for %s %w", state, err)
	}
	if !bytes.Equal(storedState.Value, []byte(nonce)) {
		return fmt.Errorf("nonce mismatch %s (expected) vs. %s (received)", string(storedState.Value), nonce)
	}
	return nil
}

// AddCode adds a code for the given state.
func (sm *Memcached) AddCode(state, code string) error {
	err := sm.client.Set(&memcache.Item{
		Key:        sm.codeKey(state),
		Value:      []byte(code),
		Expiration: expirationTime,
	})

	if err != nil {
		return errors.ErrBackendOauthAddCodeFailed.WithArgs(err)
	}
	return nil
}

func (sm *Memcached) codeKey(state string) string {
	return fmt.Sprintf("code-for-state-%s", state)
}

// Init makes sure the memcached connection is valid.
func (sm *Memcached) Init() error {
	return sm.client.Ping()
}
