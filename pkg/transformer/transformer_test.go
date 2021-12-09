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

package transformer

import (
	"encoding/json"
	"fmt"
	"github.com/greenpau/caddy-auth-portal/internal/tests"
	"testing"
)

func TestFactory(t *testing.T) {
	var testcases = []struct {
		name    string
		configs []*Config
		user    map[string]interface{}
		keys    []string
		// Expected results.
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "add authp/admin role to greenpau@outlook.com",
			user: map[string]interface{}{
				"email": "greenpau@outlook.com",
				"roles": "editor",
			},
			keys: []string{
				"challenges",
				"roles",
			},
			configs: []*Config{
				{
					Matchers: []string{
						"exact match email greenpau@outlook.com",
					},
					Actions: []string{
						"add role authp/admin authp/viewer",
						"add role authp/editor",
						"require mfa",
					},
				},
			},
			want: map[string]interface{}{
				"roles": []string{
					"editor",
					"authp/admin",
					"authp/viewer",
					"authp/editor",
				},
				"challenges": []string{
					"mfa",
				},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			tr, err := NewFactory(tc.configs)
			if err != nil {
				if tests.EvalErrWithLog(t, err, "transformer", tc.shouldErr, tc.err, msgs) {
					return
				}
			}
			if err := tr.Transform(tc.user); err != nil {
				if tests.EvalErrWithLog(t, err, "transformer", tc.shouldErr, tc.err, msgs) {
					return
				}
			}
			got := make(map[string]interface{})
			for _, k := range tc.keys {
				if v, exists := tc.user[k]; exists {
					got[k] = v
				}
			}
			tests.EvalObjectsWithLog(t, "transformer", tc.want, got, msgs)
		})
	}
}

func TestTransformData(t *testing.T) {
	var testcases = []struct {
		name      string
		args      []string
		user      map[string]interface{}
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "add role authp/user with webadmin",
			args: []string{"add", "role", "authp/user"},
			user: map[string]interface{}{
				"sub":   "webadmin",
				"roles": []string{"authp/admin"},
			},
			want: map[string]interface{}{
				"sub":   "webadmin",
				"roles": []string{"authp/admin", "authp/user"},
			},
		},
		{
			name: "add add _couchdb.roles _admin with webadmin",
			args: []string{"add", "_couchdb.roles", "_admin", "as", "string", "list"},
			user: map[string]interface{}{
				"sub":   "webadmin",
				"roles": []string{"authp/admin", "authp/user"},
			},
			want: map[string]interface{}{
				"sub":            "webadmin",
				"roles":          []interface{}{string("authp/admin"), string("authp/user")},
				"_couchdb.roles": []string{"_admin"},
			},
		},
		{
			name: "add add _couchdb.db _admin with webadmin",
			args: []string{"add", "_couchdb.db", "accounts", "as", "string"},
			user: map[string]interface{}{
				"sub":   "webadmin",
				"roles": []string{"authp/admin", "authp/user"},
			},
			want: map[string]interface{}{
				"sub":         "webadmin",
				"roles":       []interface{}{string("authp/admin"), string("authp/user")},
				"_couchdb.db": "accounts",
			},
		},
		{
			name: "as type directive is too short",
			args: []string{"add", "_couchdb.roles", "_admin", "as"},
			user: map[string]interface{}{
				"sub":   "webadmin",
				"roles": []string{"authp/admin", "authp/user"},
			},
			shouldErr: true,
			err: fmt.Errorf(
				"failed transforming %q field for %q action in %v: %v",
				"_couchdb.roles", "add", []string{"add", "_couchdb.roles", "_admin", "as"},
				"as type directive is too short",
			),
		},
		{
			name: "unsupported data type",
			args: []string{"add", "_couchdb.roles", "_admin", "as", "foo"},
			user: map[string]interface{}{
				"sub":   "webadmin",
				"roles": []string{"authp/admin", "authp/user"},
			},
			shouldErr: true,
			err: fmt.Errorf(
				"failed transforming %q field for %q action in %v: %v",
				"_couchdb.roles", "add", []string{"add", "_couchdb.roles", "_admin", "as", "foo"},
				"unsupported \"foo\" data type",
			),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			got := deepCopy(tc.user)
			if err := transformData(tc.args, got); err != nil {
				if tests.EvalErrWithLog(t, err, "transformer", tc.shouldErr, tc.err, msgs) {
					return
				}
			}
			tests.EvalObjectsWithLog(t, "transformer", tc.want, got, msgs)
		})
	}
}

func deepCopy(src map[string]interface{}) map[string]interface{} {
	if src == nil {
		return nil
	}
	j, _ := json.Marshal(src)
	m := make(map[string]interface{})
	json.Unmarshal(j, &m)
	return m
}
