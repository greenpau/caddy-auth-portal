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
	stdErrors "errors"

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

// NewMemcachedCache creates a new key manager using the specified servers.
func NewMemcachedCache(server ...string) *Memcached {
	return &Memcached{
		client: memcache.New(server...),
	}
}

// Add a key and its value to the backend.
func (sm *Memcached) Add(key string, value interface{}) error {
	encodedValue, err := json.Marshal(value)
	if err != nil {
		return errors.ErrCache.WithArgs("add", err)
	}

	err = sm.client.Set(&memcache.Item{
		Key:        key,
		Value:      encodedValue,
		Expiration: expirationTime,
	})

	if err != nil {
		return errors.ErrCache.WithArgs("add", err)
	}
	return nil
}

// Get gets a value from the cache already casted to your type.
func (sm *Memcached) Get(key string, output interface{}) error {
	value, err := sm.client.Get(key)
	if err != nil {
		return errors.ErrCache.WithArgs("get", err)
	}
	if err := json.Unmarshal(value.Value, &output); err != nil {
		return errors.ErrCache.WithArgs("get", err)
	}
	return nil
}

// Del deletes a key from the backend.
func (sm *Memcached) Del(key string) error {
	if err := sm.client.Delete(key); err != nil {
		return errors.ErrCache.WithArgs("del", err)
	}
	return nil
}

// Exists checks if the key exists in the backend.
func (sm *Memcached) Exists(key string) (bool, error) {
	_, err := sm.client.Get(key)
	if err == nil {
		return true, nil
	}
	if stdErrors.Is(err, memcache.ErrCacheMiss) {
		return false, nil
	}
	return false, errors.ErrCache.WithArgs("exists", err)
}

// Init makes sure the memcached connection is valid.
func (sm *Memcached) Init() error {
	if err := sm.client.Ping(); err != nil {
		return errors.ErrCache.WithArgs("ping", err)
	}
	return nil
}

func (sm *Memcached) String() string {
	return memcached
}
