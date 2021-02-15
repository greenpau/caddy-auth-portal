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
	"errors"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"sync"
	"time"
)

const sandboxIDCharset = "abcdefghijklmnopqrstuvwxyz0123456789"

// SandboxCacheEntry is an entry in SandboxCache.
type SandboxCacheEntry struct {
	sessionID     string
	createdAt     time.Time
	used          bool
	authenticated bool
}

// SandboxCache contains cached tokens
type SandboxCache struct {
	mu sync.RWMutex
	// The interval (in seconds) at which cache maintenance task are being triggered.
	// The default is 5 minutes (300 seconds)
	cleanupInternal int
	// The maximum number of seconds the sandbox entry is available to a user.
	maxEntryLifetime int64
	Entries          map[string]*SandboxCacheEntry
}

// NewSandboxCache returns SandboxCache instance.
func NewSandboxCache() *SandboxCache {
	c := &SandboxCache{
		cleanupInternal:  60,
		maxEntryLifetime: 300,
		Entries:          make(map[string]*SandboxCacheEntry),
	}
	go manageSandboxCache(c)
	return c
}

func manageSandboxCache(c *SandboxCache) {
	intervals := time.NewTicker(time.Second * time.Duration(c.cleanupInternal))
	for range intervals.C {
		if c == nil {
			return
		}
		c.mu.RLock()
		if c.Entries == nil {
			c.mu.RUnlock()
			continue
		}
		c.mu.RUnlock()
		c.mu.Lock()
		deleteList := []string{}
		for sandboxID, entry := range c.Entries {
			if err := entry.Valid(c.maxEntryLifetime); err != nil {
				deleteList = append(deleteList, sandboxID)
				continue
			}
		}
		if len(deleteList) > 0 {
			for _, sandboxID := range deleteList {
				delete(c.Entries, sandboxID)
			}
		}
		c.mu.Unlock()
	}
	return
}

// Add adds data to the cache.
func (c *SandboxCache) Add(sessionID string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Entries == nil {
		return "", errors.New("sandbox cache is not available")
	}
	sandboxID := utils.GetRandomStringFromRangeWithCharset(64, 96, sandboxIDCharset)
	c.Entries[sandboxID] = &SandboxCacheEntry{
		sessionID: sessionID,
		createdAt: time.Now().UTC(),
	}
	return sandboxID, nil
}

// Delete removes cached data entry.
func (c *SandboxCache) Delete(sandboxID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.Entries, sandboxID)
	return nil
}

// Get returns cached data entry.
func (c *SandboxCache) Get(sandboxID string) (string, error) {
	if err := parseSandboxID(sandboxID); err != nil {
		return "", err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if entry, exists := c.Entries[sandboxID]; exists {
		if err := entry.Valid(c.maxEntryLifetime); err != nil {
			return "", err
		}
		return entry.sessionID, nil
	}
	return "", errors.New("sandbox id not found")
}

func (e *SandboxCacheEntry) Valid(max int64) error {
	if e.authenticated {
		return errors.New("sandbox id already authenticated")
	}
	diff := time.Now().UTC().Unix() - e.createdAt.Unix()
	if diff > max {
		return errors.New("sandbox id expired")
	}
	return nil
}

// parseSandboxID checks sandbox id for format requirements.
func parseSandboxID(s string) error {
	if len(s) > 96 || len(s) < 64 {
		return errors.New("sandbox id length is outside of 64-64 character range")
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return errors.New("sandbox id contains invalid characters")
		}
	}
	return nil
}
