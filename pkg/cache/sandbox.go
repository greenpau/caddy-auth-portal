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
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/greenpau/caddy-authorize/pkg/user"
)

const defaultSandboxCleanupInternal int = 60
const minSandboxCleanupInternal int = 0
const defaultSandboxMaxEntryLifetime int = 300
const minSandboxMaxEntryLifetime int = 60

// SandboxCacheEntry is an entry in SandboxCache.
type SandboxCacheEntry struct {
	sandboxID string
	createdAt time.Time
	user      *user.User
	// When set to true, the sandbox entry is no longer active.
	expired bool
}

// SandboxCache contains cached tokens
type SandboxCache struct {
	mu sync.RWMutex
	// The interval (in seconds) at which cache maintenance task are being triggered.
	// The default is 5 minutes (300 seconds)
	cleanupInternal int
	// The maximum number of seconds the cached entry is available to a user.
	maxEntryLifetime int
	// If set to true, then the cache is being managed.
	managed bool
	// exit channel
	exit    chan bool
	Entries map[string]*SandboxCacheEntry
}

// NewSandboxCache returns SandboxCache instance.
func NewSandboxCache() *SandboxCache {
	return &SandboxCache{
		cleanupInternal:  defaultSandboxCleanupInternal,
		maxEntryLifetime: defaultSandboxMaxEntryLifetime,
		Entries:          make(map[string]*SandboxCacheEntry),
		exit:             make(chan bool),
	}
}

// SetCleanupInterval sets cache management interval.
func (c *SandboxCache) SetCleanupInterval(i int) error {
	if i < 1 {
		return fmt.Errorf("sandbox cache cleanup interval must be equal to or greater than %d", minSandboxCleanupInternal)
	}
	c.cleanupInternal = i
	return nil
}

// SetMaxEntryLifetime sets cache management max entry lifetime in seconds.
func (c *SandboxCache) SetMaxEntryLifetime(i int) error {
	if i < 60 {
		return fmt.Errorf("sandbox cache max entry lifetime must be equal to or greater than %d seconds", minSandboxMaxEntryLifetime)
	}
	c.maxEntryLifetime = i
	return nil
}

func manageSandboxCache(c *SandboxCache) {
	c.managed = true
	intervals := time.NewTicker(time.Second * time.Duration(c.cleanupInternal))
	for range intervals.C {
		if c == nil {
			continue
		}
		c.mu.Lock()
		select {
		case <-c.exit:
			c.managed = false
			break
		default:
			break
		}
		if !c.managed {
			c.mu.Unlock()
			break
		}
		if c.Entries == nil {
			c.mu.Unlock()
			continue
		}
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

// Run starts management of SandboxCache instance.
func (c *SandboxCache) Run() {
	if c.managed {
		return
	}
	go manageSandboxCache(c)
}

// Stop stops management of SandboxCache instance.
func (c *SandboxCache) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.managed = false
}

// GetCleanupInterval returns cleanup interval.
func (c *SandboxCache) GetCleanupInterval() int {
	return c.cleanupInternal
}

// GetMaxEntryLifetime returns max entry lifetime.
func (c *SandboxCache) GetMaxEntryLifetime() int {
	return c.maxEntryLifetime
}

// Add adds user to the cache.
func (c *SandboxCache) Add(sandboxID string, u *user.User) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Entries == nil {
		return errors.New("sandbox cache is not available")
	}
	c.Entries[sandboxID] = &SandboxCacheEntry{
		sandboxID: sandboxID,
		createdAt: time.Now().UTC(),
		user:      u,
	}
	return nil
}

// Delete removes cached user entry.
func (c *SandboxCache) Delete(sandboxID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Entries == nil {
		return errors.New("sandbox cache is not available")
	}
	_, exists := c.Entries[sandboxID]
	if !exists {
		return errors.New("cached sandbox id not found")
	}
	delete(c.Entries, sandboxID)
	return nil
}

// Get returns cached user entry.
func (c *SandboxCache) Get(sandboxID string) (*user.User, error) {
	if err := parseCacheID(sandboxID); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if entry, exists := c.Entries[sandboxID]; exists {
		if err := entry.Valid(c.maxEntryLifetime); err != nil {
			return nil, err
		}
		return entry.user, nil
	}
	return nil, errors.New("cached sandbox id not found")
}

// Expire expires a particular sandbox entry.
func (c *SandboxCache) Expire(sandboxID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, exists := c.Entries[sandboxID]; exists {
		entry.expired = true
	}
	return
}

// Valid checks whether SandboxCacheEntry is non-expired.
func (e *SandboxCacheEntry) Valid(max int) error {
	if e.expired {
		return errors.New("sandbox cached entry is no longer in use")
	}
	diff := time.Now().UTC().Unix() - e.createdAt.Unix()
	if diff > int64(max) {
		return errors.New("sandbox cached entry expired")
	}
	return nil
}
