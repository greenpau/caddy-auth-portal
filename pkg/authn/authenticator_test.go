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

package authn

import (
	"fmt"
	"github.com/greenpau/caddy-auth-jwt/pkg/acl"
	"github.com/greenpau/caddy-auth-portal/internal/tests"
	"github.com/greenpau/caddy-auth-portal/internal/utils"
	"github.com/greenpau/caddy-auth-portal/pkg/backends"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/local"
	"github.com/greenpau/caddy-auth-portal/pkg/errors"

	"testing"
)

func TestNewAuthenticator(t *testing.T) {
	db, err := tests.CreateTestDatabase("TestNewAuthenticator")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	dbPath := db.GetPath()
	t.Logf("%v", dbPath)

	var testcases = []struct {
		name      string
		disabled  bool
		portals   []*Authenticator
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "test non-primary portal in default context",
			portals: []*Authenticator{
				&Authenticator{},
			},
			shouldErr: true,
			err:       errors.ErrInstanceManagerValidate.WithArgs("portal-default-000001", "primary instance not found"),
		},
		{
			name: "test primary portal in default context without authentication backends",
			portals: []*Authenticator{
				&Authenticator{
					PrimaryInstance: true,
					AccessListConfigs: []*acl.RuleConfiguration{
						{
							Conditions: []string{
								"partial match issuer localhost",
								"always match roles any",
							},
							Action: `allow`,
						},
					},
				},
			},
			shouldErr: true,
			err:       errors.ErrNoBackendsFound.WithArgs("default", "portal-default-000001"),
		},
		{
			name: "test primary portal in default context with empty backend configuration",
			portals: []*Authenticator{
				&Authenticator{
					PrimaryInstance: true,
					AccessListConfigs: []*acl.RuleConfiguration{
						{
							Conditions: []string{
								"partial match issuer localhost",
								"always match roles any",
							},
							Action: `allow`,
						},
					},
					BackendConfigs: []backends.Config{
						backends.Config{},
					},
				},
			},
			shouldErr: true,
			err: errors.ErrBackendConfigurationFailed.WithArgs(
				"default", "portal-default-000001",
				errors.ErrBackendConfigureEmptyConfig,
			),
		},
		{
			name: "test primary portal in default context",
			portals: []*Authenticator{
				&Authenticator{
					PrimaryInstance: true,
					AccessListConfigs: []*acl.RuleConfiguration{
						{
							Conditions: []string{
								"partial match issuer localhost",
								"always match roles any",
							},
							Action: `allow`,
						},
					},
					BackendConfigs: []backends.Config{
						backends.Config{
							Local: &local.Config{
								Name:   "local_backend",
								Method: "local",
								Realm:  "local",
								Path:   dbPath,
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.disabled {
				return
			}
			AuthManager = NewInstanceManager()
			var err error
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			logger := utils.NewLogger()
			portals := []*Authenticator{}

			for _, p := range tc.portals {
				p.SetLogger(logger)
				if err := p.Provision(); err != nil {
					if tests.EvalErrWithLog(t, err, tc.want, tc.shouldErr, tc.err, msgs) {
						return
					}
				}
				if err := p.Validate(); err != nil {
					if tests.EvalErrWithLog(t, err, tc.want, tc.shouldErr, tc.err, msgs) {
						return
					}
				}
				portals = append(portals, p)
			}
			if tests.EvalErrWithLog(t, err, tc.want, tc.shouldErr, tc.err, msgs) {
				return
			}
		})
	}
}
