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
	"strings"
	"testing"
	"time"
)

func TestParseSandboxID(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		shouldErr bool
		err       error
	}{
		{
			name: "valid sandbox id",
			id:   utils.GetRandomStringFromRangeWithCharset(64, 96, sandboxIDCharset),
		},
		{
			name:      "sandbox id is too short",
			id:        "foobar",
			shouldErr: true,
			err:       errors.New("sandbox id length is outside of 64-64 character range"),
		},
		{
			name:      "sandbox id is too long",
			id:        strings.Repeat("foobar", 128),
			shouldErr: true,
			err:       errors.New("sandbox id length is outside of 64-64 character range"),
		},
		{
			name:      "sandbox id is invalid character",
			id:        strings.Repeat("foobar", 6) + "A" + strings.Repeat("foobar", 6),
			shouldErr: true,
			err:       errors.New("sandbox id contains invalid characters"),
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("test %d: %s", i, tc.name)
			err := parseSandboxID(tc.id)
			if tc.shouldErr && err == nil {
				t.Fatalf("test %d FAIL: expected error, but got success", i)
			}
			if !tc.shouldErr && err != nil {
				t.Fatalf("test %d FAIL: expected success, but got error: %s", i, err)
			}
			if tc.shouldErr {
				if err.Error() != tc.err.Error() {
					t.Fatalf("test %d FAIL: unexpected error, got: %v, expected: %v", i, err, tc.err)
				}
				t.Logf("test %d PASS: received expected error: %s", i, err)
				return
			}
			t.Logf("test %d PASS: received valid sandbox id", i)
		})
	}
}

func TestNewSandboxCache(t *testing.T) {
	tests := []struct {
		name             string
		opts             map[string]interface{}
		cleanupInterval  int
		maxEntryLifetime int64
		shouldErr        bool
		err              error
	}{
		{
			name: "valid configuration options",
			opts: map[string]interface{}{
				"cleanup_interval":   1,
				"max_entry_lifetime": 60,
			},
			cleanupInterval:  1,
			maxEntryLifetime: 60,
		},
		{
			name: "invalid cleanup interval with zero value",
			opts: map[string]interface{}{
				"cleanup_interval": 0,
			},
			shouldErr: true,
			err:       errors.New("sandbox cache cleanup interval must be equal to or greater than 0"),
		},
		{
			name: "invalid cleanup interval with string value",
			opts: map[string]interface{}{
				"cleanup_interval": "test",
			},
			shouldErr: true,
			err:       errors.New("invalid sandbox cache configuration option cleanup_interval value type string"),
		},
		{
			name: "invalid max entry lifetime with string value",
			opts: map[string]interface{}{
				"max_entry_lifetime": "test",
			},
			shouldErr: true,
			err:       errors.New("invalid sandbox cache configuration option max_entry_lifetime value type string"),
		},
		{
			name: "invalid max entry lifetime with unsupported value",
			opts: map[string]interface{}{
				"max_entry_lifetime": 15,
			},
			shouldErr: true,
			err:       errors.New("sandbox cache max entry lifetime must be equal to or greater than 60 seconds"),
		},
		{
			name: "unsupported configuration option",
			opts: map[string]interface{}{
				"foo": "bar",
			},
			shouldErr: true,
			err:       errors.New("unsupported sandbox cache configuration option foo = bar"),
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("test %d: %s", i, tc.name)
			c, err := NewSandboxCache(tc.opts)
			if tc.shouldErr && err == nil {
				t.Fatalf("test %d FAIL: expected error, but got success", i)
			}
			if !tc.shouldErr && err != nil {
				t.Fatalf("test %d FAIL: expected success, but got error: %s", i, err)
			}
			if tc.shouldErr {
				if err.Error() != tc.err.Error() {
					t.Fatalf("test %d FAIL: unexpected error, got: %v, expected: %v", i, err, tc.err)
				}
				t.Logf("test %d PASS: received expected error: %s", i, err)
				return
			}
			if c.GetCleanupInterval() != tc.cleanupInterval {
				t.Fatalf("test %d FAIL: cleanup interval mismatch: %d (received) vs %d (expected)", i, c.GetCleanupInterval(), tc.cleanupInterval)
			}
			if c.GetMaxEntryLifetime() != tc.maxEntryLifetime {
				t.Fatalf("test %d FAIL: max entry lifetime  mismatch: %d (received) vs %d (expected)", i, c.GetMaxEntryLifetime(), tc.maxEntryLifetime)

			}
			t.Logf("test %d PASS: created sandbox cache", i)
		})
	}
}

func TestSandboxCache(t *testing.T) {
	opts := map[string]interface{}{
		"cleanup_interval":   1,
		"max_entry_lifetime": 60,
	}

	c, err := NewSandboxCache(opts)
	if err != nil {
		t.Fatalf("FAIL: unexpected error during sandbox cache creation: %s", err)
	}

	sessionID := "foobar"

	sandboxID, err := c.Add(sessionID)
	if err != nil {
		t.Fatalf("FAIL: unexpected error when adding an entry: %s", err)
	}

	cachedSessionID, err := c.Get(sandboxID)
	if err != nil {
		t.Fatalf("FAIL: unexpected error when pulling an entry: %s", err)
	}

	if sessionID != cachedSessionID {
		t.Fatalf("FAIL: session id mismatch: %s (received) vs %s (expected)", cachedSessionID, sessionID)
	}

	if err := c.Delete(sandboxID); err != nil {
		t.Fatalf("FAIL: unexpected error when deleting an entry: %s", err)
	}

	cachedSessionID, err = c.Get(sandboxID)
	if err == nil {
		t.Fatalf("FAIL: expected error, but got success: %s", cachedSessionID)
	}

	// attempt getting entry for invalid sandbox id
	if _, err = c.Get("foobar"); err == nil {
		t.Fatalf("FAIL: expected error getting invalid sandbox id, but got success")
	} else {
		expError := errors.New("sandbox id length is outside of 64-64 character range")
		if err.Error() != expError.Error() {
			t.Fatalf("FAIL: unexpected error while getting invalid sandbox id, got: %v, expected: %v", err, expError)
		}
	}

	// attempt getting expired sandbox id
	c.mu.Lock()
	sandboxID = utils.GetRandomStringFromRangeWithCharset(64, 96, sandboxIDCharset)
	c.Entries[sandboxID] = &SandboxCacheEntry{
		sessionID:     "foo",
		authenticated: true,
		createdAt:     time.Now().UTC(),
	}
	c.mu.Unlock()
	if _, err = c.Get(sandboxID); err == nil {
		t.Fatalf("FAIL: expected error getting expired sandbox id, but got success")
	} else {
		expError := errors.New("sandbox id already authenticated")
		if err.Error() != expError.Error() {
			t.Fatalf("FAIL: unexpected error while getting expired sandbox id, got: %v, expected: %v", err, expError)
		}
	}

	// nullify entries, and try getting one.
	c.mu.Lock()
	c.Entries = nil
	c.mu.Unlock()
	if _, err = c.Add(sessionID); err == nil {
		t.Fatalf("FAIL: expected error adding to nil entries, but got success")
	} else {
		expError := errors.New("sandbox cache is not available")
		if err.Error() != expError.Error() {
			t.Fatalf("FAIL: unexpected error while adding to nil entries, got: %v, expected: %v", err, expError)
		}
	}

	time.Sleep(2 * time.Second)
	if !c.managed {
		t.Fatal("FAIL: expected cache management function running, but it is not")
	}
	t.Logf("cache management function running: %t", c.managed)

	// nullify entries
	c.mu.Lock()
	c.Entries = nil
	c.mu.Unlock()
	time.Sleep(2 * time.Second)

	// create expired entries
	c.mu.Lock()
	c.Entries = make(map[string]*SandboxCacheEntry)
	sandboxID = utils.GetRandomStringFromRangeWithCharset(64, 96, sandboxIDCharset)
	c.Entries[sandboxID] = &SandboxCacheEntry{
		sessionID:     "foo",
		authenticated: true,
		createdAt:     time.Now().UTC(),
	}
	sandboxID = utils.GetRandomStringFromRangeWithCharset(64, 96, sandboxIDCharset)
	c.Entries[sandboxID] = &SandboxCacheEntry{
		sessionID: "bar",
		createdAt: time.Now().Add(time.Duration(-120) * time.Second).UTC(),
	}
	for k, v := range c.Entries {
		t.Logf("cached entry %s: created at: %s, entry: %v", k, v.createdAt, v)
	}
	c.mu.Unlock()
	time.Sleep(2 * time.Second)

	if len(c.Entries) != 0 {
		t.Fatalf("FAIL: expected sandbox cache be empty, found %d entries", len(c.Entries))
	}
	t.Logf("found expected empty sandbox cache")

	// exit cache management function
	c.exit <- true
	time.Sleep(1 * time.Second)
	if c.managed {
		t.Fatal("FAIL: expected cache management function stopped, but it is not")
	}
	t.Logf("cache management function running: %t", c.managed)

}
