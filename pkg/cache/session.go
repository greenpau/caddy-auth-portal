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

package cache

import (
	jwtclaims "github.com/greenpau/caddy-auth-jwt/pkg/claims"
	//"log"
	"sync"
	"time"
)

// SessionCache contains cached tokens
type SessionCache struct {
	mu      sync.RWMutex
	Entries map[string]interface{}
}

// NewSessionCache returns SessionCache instance.
func NewSessionCache() *SessionCache {
	c := &SessionCache{
		Entries: map[string]interface{}{},
	}
	go manageSessionCache(c)
	return c
}

func manageSessionCache(cache *SessionCache) {
	intervals := time.NewTicker(time.Minute * time.Duration(5))
	for range intervals.C {
		//log.Printf("managing cache")
		if cache == nil {
			//log.Printf("cache is nil")
			return
		}
		cache.mu.RLock()
		if cache.Entries == nil {
			//log.Printf("cache entries is nil")
			cache.mu.RUnlock()
			continue
		}
		cache.mu.RUnlock()
		cache.mu.Lock()
		//log.Printf("cache entries count: %d", len(cache.Entries))
		for entryID, data := range cache.Entries {
			//log.Printf("entering cache entry: %s", entryID)
			switch data.(type) {
			case map[string]interface{}:
				//log.Printf("cached entry is map[string]interface")
				dataset := data.(map[string]interface{})
				//log.Printf("cached entry data: %v", dataset)
				if v, exists := dataset["claims"]; exists {
					claims := v.(*jwtclaims.UserClaims)
					//log.Printf("entering cache claims: %v", claims)
					if err := claims.Valid(); err != nil {
						delete(cache.Entries, entryID)
					}
				}
			default:
				continue
			}
		}
		cache.mu.Unlock()
	}
	return
}

// Add adds data to the cache.
func (c *SessionCache) Add(entryID string, data interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Entries[entryID] = data
	return nil
}

// Delete removes cached data entry.
func (c *SessionCache) Delete(entryID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.Entries, entryID)
	return nil
}

// Get returns cached data entry.
func (c *SessionCache) Get(entryID string) map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	data, exists := c.Entries[entryID]
	if !exists {
		return nil
	}
	switch data.(type) {
	case map[string]interface{}:
		return data.(map[string]interface{})
	}
	return nil
}
