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

package tag

import (
	"github.com/greenpau/caddy-auth-portal/internal/tests"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/local"
	"testing"
)

func TestTagCompliance(t *testing.T) {
	testcases := []struct {
		name      string
		entry     interface{}
		opts      *Options
		shouldErr bool
		err       error
	}{
		{
			name:  "test local backend",
			entry: &local.Backend{},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs, err := GetTagCompliance(tc.entry, tc.opts)
			if tests.EvalErrWithLog(t, err, nil, tc.shouldErr, tc.err, msgs) {
				return
			}
		})
	}
}
