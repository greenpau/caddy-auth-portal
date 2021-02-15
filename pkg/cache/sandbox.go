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
	"fmt"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"sync"
	"time"
)

const sandboxIDCharset = "abcdefghijklmnopqrstuvwxyz0123456789"
const defaultCleanupInternal int = 60
const defaultMaxEntryLifetime int64 = 300
const minCleanupInternal int = 0
const minMaxEntryLifetime int64 = 60

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
	// If set to true, then the cache is being managed.
	managed bool
	// exit channel
	exit    chan bool
	Entries map[string]*SandboxCacheEntry
}

// NewSandboxCache returns SandboxCache instance.
func NewSandboxCache(opts map[string]interface{}) (*SandboxCache, error) {
	c := &SandboxCache{
		cleanupInternal:  defaultCleanupInternal,
		maxEntryLifetime: defaultMaxEntryLifetime,
		Entries:          make(map[string]*SandboxCacheEntry),
		exit:             make(chan bool),
	}
	if opts != nil {
		for k, v := range opts {
			switch k {
			case "cleanup_interval":
				switch v.(type) {
				case int:
					c.cleanupInternal = v.(int)
				default:
					return nil, fmt.Errorf("invalid sandbox cache configuration option %s value type %T", k, v)
				}
			case "max_entry_lifetime":
				switch v.(type) {
				case int:
					c.maxEntryLifetime = int64(v.(int))
				default:
					return nil, fmt.Errorf("invalid sandbox cache configuration option %s value type %T", k, v)
				}
			default:
				return nil, fmt.Errorf("unsupported sandbox cache configuration option %s = %v", k, v)
			}
		}
	}

	if c.cleanupInternal < 1 {
		return nil, fmt.Errorf("sandbox cache cleanup interval must be equal to or greater than %d", minCleanupInternal)
	}
	if c.maxEntryLifetime < 60 {
		return nil, fmt.Errorf("sandbox cache max entry lifetime must be equal to or greater than %d seconds", minMaxEntryLifetime)
	}

	go manageSandboxCache(c)
	return c, nil
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

// GetCleanupInterval returns cleanup interval.
func (c *SandboxCache) GetCleanupInterval() int {
	return c.cleanupInternal
}

// GetMaxEntryLifetime returns max entry lifetime.
func (c *SandboxCache) GetMaxEntryLifetime() int64 {
	return c.maxEntryLifetime
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

// Valid checks whether SandboxCacheEntry is non-authenticated and not expired.
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
