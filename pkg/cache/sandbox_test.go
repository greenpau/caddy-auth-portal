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
	"strings"
	"testing"
	// "time"

	"github.com/greenpau/caddy-auth-portal/internal/tests"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
)

func TestParseSandboxID(t *testing.T) {
	testcases := []struct {
		name      string
		id        string
		shouldErr bool
		err       error
	}{
		{
			name: "valid sandbox id",
			id:   utils.GetRandomStringFromRange(32, 96),
		},
		{
			name:      "sandbox id is too short",
			id:        "foobar",
			shouldErr: true,
			err:       errors.New("cached id length is outside of 32-96 character range"),
		},
		{
			name:      "sandbox id is too long",
			id:        strings.Repeat("foobar", 128),
			shouldErr: true,
			err:       errors.New("cached id length is outside of 32-96 character range"),
		},
		{
			name:      "sandbox id is invalid character",
			id:        strings.Repeat("foobar", 6) + " " + strings.Repeat("foobar", 6),
			shouldErr: true,
			err:       errors.New("cached id contains invalid characters"),
		},
	}

	for i, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test %d, name: %s", i, tc.name)}
			err := parseCacheID(tc.id)
			if tests.EvalErrWithLog(t, err, "parse sandbox id", tc.shouldErr, tc.err, msgs) {
				return
			}
		})
	}
}

func TestNewSandboxCache(t *testing.T) {
	testcases := []struct {
		name      string
		input     map[string]interface{}
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "valid configuration options",
			want: map[string]interface{}{
				"cleanup_interval":   1,
				"max_entry_lifetime": 60,
			},
			input: map[string]interface{}{
				"cleanup_interval":   1,
				"max_entry_lifetime": 60,
			},
		},
		{
			name: "invalid cleanup interval with zero value",
			input: map[string]interface{}{
				"cleanup_interval": 0,
			},
			shouldErr: true,
			err:       errors.New("sandbox cache cleanup interval must be equal to or greater than 0"),
		},
		{
			name: "invalid max entry lifetime with unsupported value",
			input: map[string]interface{}{
				"cleanup_interval":   1,
				"max_entry_lifetime": 15,
			},
			shouldErr: true,
			err:       errors.New("sandbox cache max entry lifetime must be equal to or greater than 60 seconds"),
		},
	}

	for i, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test %d, name: %s", i, tc.name)}
			c := NewSandboxCache()
			for k, v := range tc.input {
				var err error
				switch k {
				case "cleanup_interval":
					err = c.SetCleanupInterval(v.(int))
				case "max_entry_lifetime":
					err = c.SetMaxEntryLifetime(v.(int))
				}
				if err != nil {
					if tests.EvalErrWithLog(t, err, "sandbox cache", tc.shouldErr, tc.err, msgs) {
						return
					}
				}
			}
			got := make(map[string]interface{})
			got["cleanup_interval"] = c.GetCleanupInterval()
			got["max_entry_lifetime"] = c.GetMaxEntryLifetime()
			tests.EvalObjectsWithLog(t, "sandbox cache", tc.want, got, msgs)
		})
	}
}
