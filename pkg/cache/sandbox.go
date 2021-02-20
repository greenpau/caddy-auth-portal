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
	"strings"
	"sync"
	"time"

	"github.com/greenpau/caddy-auth-portal/pkg/utils"
)

const sandboxIDCharset = "abcdefghijklmnopqrstuvwxyz0123456789"
const defaultCleanupInternal int = 60
const defaultMaxEntryLifetime int64 = 300
const minCleanupInternal int = 0
const minMaxEntryLifetime int64 = 60

var stepNameMap = map[string]int{
	"init":      0,
	"routed":    1,
	"landed":    2,
	"submitted": 3,
	"denied":    4,
	"allowed":   5,
	"resolved":  6,
}

var stepNumMap = map[int]string{
	0: "init",
	1: "routed",
	2: "landed",
	3: "submitted",
	4: "denied",
	5: "allowed",
	6: "resolved",
}

// SandboxHurdle holds the information about a particular sandbox hurdle that
// a user needs to pass to get out of the sandbox.
type SandboxHurdle struct {
	// The name of the hurdle. The range of values are mfa and accept_terms.
	name string
	// The step is the name of a stage within the hurdle that a user already passed.
	// It allows evaluating whether the next step in the sandbox process is allowed.
	// The steps are: 0 (init), 1 (routed), 2 (landed), 3 (submitted), and 4 (resolved).
	step int
	// The verdict contains the keyword that would be injected to user's
	// metadata upon successful exit from a sandbox. The valid values are
	// 0 (tbd), 1 (deny), 2 (allow)
	verdict int
}

// NewSandboxHurdle returns an instance of SandboxHurdle.
func NewSandboxHurdle(name string, opts map[string]interface{}) (*SandboxHurdle, error) {
	name = strings.TrimSuffix(name, "_required")
	h := &SandboxHurdle{
		name:    name,
		step:    0,
		verdict: 0,
	}
	if opts == nil {
		return h, nil
	}

	for k, v := range opts {
		switch k {
		case "init_step":
			switch v.(type) {
			case int:
				h.step = v.(int)
				if h.step < 0 || h.step > 2 {
					return nil, fmt.Errorf("invalid sandbox hurdle configuration option %s value out of range %d", k, h.step)
				}
			case string:
				step := v.(string)
				stepNum, exists := stepNameMap[step]
				if !exists {
					return nil, fmt.Errorf("invalid sandbox hurdle configuration option %s unsupported value %s", k, step)
				}
				h.step = stepNum
			default:
				return nil, fmt.Errorf("invalid sandbox hurdle configuration option %s value type %T", k, v)
			}
		default:
			return nil, fmt.Errorf("unsupported sandbox hurdle configuration option %s = %v", k, v)
		}
	}

	return h, nil
}

// SandboxCacheEntry is an entry in SandboxCache. It holds
// session identifier and a collection of sandbox.
type SandboxCacheEntry struct {
	sessionID string
	createdAt time.Time
	// secret is the value of a short-lived cookie to authenticate
	// request to the sandbox.
	secret string
	// the hurdles to overcome to get out of the sandbox.
	hurdles []*SandboxHurdle
	// the closed set when there are no hurdles to overcome,
	// i.e. the verdict rendered and accepted by the requestor.
	closed bool
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
func (c *SandboxCache) Add(sessionID string, hurdleNames []string) (map[string]string, error) {
	if hurdleNames == nil || len(hurdleNames) == 0 {
		return nil, errors.New("no hurdle names found")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	resp := make(map[string]string)
	if c.Entries == nil {
		return nil, errors.New("sandbox cache is not available")
	}
	sandboxID := utils.GetRandomStringFromRangeWithCharset(64, 96, sandboxIDCharset)
	secret := utils.GetRandomStringFromRangeWithCharset(64, 96, sandboxIDCharset)
	entry := &SandboxCacheEntry{
		sessionID: sessionID,
		secret:    secret,
		createdAt: time.Now().UTC(),
	}
	hurdles := []*SandboxHurdle{}
	for _, hurdleName := range hurdleNames {
		hurdle, err := NewSandboxHurdle(hurdleName, nil)
		if err != nil {
			return nil, err
		}
		hurdles = append(hurdles, hurdle)
	}
	entry.hurdles = hurdles
	c.Entries[sandboxID] = entry
	resp["id"] = sandboxID
	resp["secret"] = secret
	return resp, nil
}

// Delete removes cached data entry.
func (c *SandboxCache) Delete(sandboxID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.Entries[sandboxID]; !exists {
		return errors.New("sandbox id not found")
	}
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

// Valid checks whether SandboxCacheEntry is non-expired.
func (e *SandboxCacheEntry) Valid(max int64) error {
	if e.closed {
		return errors.New("sandbox cached entry is no longer in use")
	}
	diff := time.Now().UTC().Unix() - e.createdAt.Unix()
	if diff > max {
		return errors.New("sandbox cached entry expired")
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

// Jump returns error if the jump to a particular step is denied.
func (c *SandboxCache) Jump(sandboxID, hurdleName, stepName string) error {
	if err := parseSandboxID(sandboxID); err != nil {
		return err
	}
	stepNum, exists := stepNameMap[stepName]
	if !exists {
		return fmt.Errorf("invalid step name: %s", stepName)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, exists := c.Entries[sandboxID]; exists {
		if err := entry.Valid(c.maxEntryLifetime); err != nil {
			return err
		}
		for _, hurdle := range entry.hurdles {
			switch hurdle.verdict {
			case 0:
				if hurdle.name != hurdleName {
					entry.closed = true
					return fmt.Errorf("detected invalid jump to %s, no verdict for %s yet", hurdleName, hurdle.name)
				}
				if hurdle.step >= stepNum {
					entry.closed = true
					return fmt.Errorf("detected potential reuse, invalid jump to step %s of %s, but current step is %s", stepName, hurdleName, stepNumMap[hurdle.step])
				}
				hurdle.step = stepNum
				switch stepNum {
				case 4:
					// deny
					hurdle.verdict = 1
				case 5:
					// allow
					hurdle.verdict = 2
				}
				return nil
			case 1:
				// deny
				entry.closed = true
				return fmt.Errorf("sandbox verdict is %s deny", hurdle.name)
			case 2:
				// allow
				if hurdle.name == hurdleName {
					entry.closed = true
					return fmt.Errorf("detected potential reuse, invalid jump to step %s of %s, while it is %s", stepName, hurdleName, stepNumMap[hurdle.step])
				}
			default:
				return fmt.Errorf("sandbox unsupported verdict of %d for %s", hurdle.verdict, hurdle.name)
			}
		}

		return nil
	}
	return errors.New("sandbox id not found")
}

// Next returns next steps, if any, for the sandbox processing..
func (c *SandboxCache) Next(sandboxID string) (bool, string, error) {
	if err := parseSandboxID(sandboxID); err != nil {
		return false, "", err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, exists := c.Entries[sandboxID]; exists {
		if err := entry.Valid(c.maxEntryLifetime); err != nil {
			return false, "", err
		}
		for _, hurdle := range entry.hurdles {
			switch hurdle.verdict {
			case 0:
				if hurdle.step == 0 {
					// TODO(greenpau): see how to determine next steps.
					return false, hurdle.name, nil
				}
				entry.closed = true
				return false, "", fmt.Errorf("detected invalid jump to status, while no verdict for %s yet", hurdle.name)
			case 1:
				// denied
				entry.closed = true
				return false, "", fmt.Errorf("sandbox verdict is %s deny", hurdle.name)
			case 2:
				// allowed
			default:
				return false, "", fmt.Errorf("sandbox unsupported verdict of %d for %s", hurdle.verdict, hurdle.name)
			}
		}

		return true, "", nil
	}
	return false, "", errors.New("sandbox id not found")
}
