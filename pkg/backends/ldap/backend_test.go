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

package ldap

import (
	"fmt"
	"github.com/greenpau/caddy-auth-portal/pkg/enums/operator"
	// "github.com/greenpau/caddy-auth-portal/pkg/errors"
	"github.com/greenpau/go-identity/pkg/requests"
	// "path"
	// "path/filepath"
	"strings"

	"github.com/greenpau/caddy-auth-portal/internal/tests"
	"github.com/greenpau/caddy-auth-portal/internal/utils"
	"testing"
)

func TestBackend(t *testing.T) {
	/*
		db, err := tests.CreateTestDatabase("TestLdapBackend")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		dbPath := db.GetPath()
		t.Logf("%v", dbPath)
	*/
	testcases := []struct {
		name         string
		configs      []*Config
		testRequests bool
		want         map[string]interface{}
		shouldErr    bool
		err          error
	}{
		{
			name: "test ldap backend",
			configs: []*Config{
				&Config{
					Name:         "ldap_backend1",
					Method:       "ldap",
					Realm:        "domain1.contoso.com",
					SearchBaseDN: "DC=DOMAIN1,DC=CONTOSO,DC=COM",
					Servers: []AuthServer{
						{
							Address: "ldaps://localhost:636",
						},
					},
					BindUsername: "CN=authzsvc,OU=Service Accounts,OU=Administrative Accounts,DC=DOMAIN1,DC=CONTOSO,DC=COM",
					BindPassword: "P@ssW0rd123",
					Groups: []UserGroup{
						{
							GroupDN: "CN=Admins,OU=Security,OU=Groups,DC=DOMAIN1,DC=CONTOSO,DC=COM",
							Roles:   []string{"admin"},
						},
						{
							GroupDN: "CN=Editors,OU=Security,OU=Groups,DC=DOMAIN1,DC=CONTOSO,DC=COM",
							Roles:   []string{"editor"},
						},
						{
							GroupDN: "CN=Viewers,OU=Security,OU=Groups,DC=DOMAIN1,DC=CONTOSO,DC=COM",
							Roles:   []string{"viewer"},
						},
					},
				},
			},
			testRequests: true,
			want: map[string]interface{}{
				"ldap_backend1_method": "ldap",
				"ldap_backend1_realm":  "domain1.contoso.com",
				"ldap_backend1_config": []string{
					"name ldap_backend1",
					"method ldap",
					"realm domain1.contoso.com",
					"",
				},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var backends []*Backend
			got := make(map[string]interface{})
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			logger := utils.NewLogger()

			for j, config := range tc.configs {
				msgs = append(msgs, fmt.Sprintf("config:\n%v", config))
				//if config.Realm != "" {
				//	config.Realm = fmt.Sprintf("%s%d", config.Realm, i)
				//}

				b := NewDatabaseBackend(config, logger)
				err := b.Configure()
				if len(tc.configs) == 1 || j > 0 {
					if tests.EvalErrWithLog(t, err, "configure", tc.shouldErr, tc.err, msgs) {
						return
					}
				}
				err = b.Validate()
				if len(tc.configs) == 1 || j > 0 {
					if tests.EvalErrWithLog(t, err, "validate", tc.shouldErr, tc.err, msgs) {
						return
					}
				}
				backends = append(backends, b)
			}

			for _, b := range backends {
				for _, op := range []operator.Type{
					operator.ChangePassword,
					operator.AddKeySSH,
					operator.AddKeyGPG,
					operator.GetPublicKeys,
					operator.DeletePublicKey,
					operator.AddMfaToken,
					operator.GetMfaTokens,
					operator.DeleteMfaToken,
					operator.AddUser,
					operator.GetUser,
					operator.GetUsers,
					operator.DeleteUser,
				} {
					b.Request(op, &requests.Request{
						User: requests.User{
							Username: tests.TestUser1,
							Email:    tests.TestEmail1,
						},
					})
				}

				got[b.GetName()+"_realm"] = b.GetRealm()
				got[b.GetName()+"_method"] = b.GetMethod()
				got[b.GetName()+"_config"] = strings.Split(b.GetConfig(), "\n")
				// t.Logf("%d", len(globalAuthenticators))
			}
			tests.EvalObjectsWithLog(t, "config", tc.want, got, msgs)
		})
	}
}

/*
func TestAuthenticate(t *testing.T) {
	db, err := tests.CreateTestDatabase("TestLocalBackend")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	dbPath := db.GetPath()
	t.Logf("%v", dbPath)

	config := &Config{
		Name:   "local_backend",
		Method: "local",
		Realm:  "local",
		Path:   dbPath,
	}

	testcases := []struct {
		name      string
		config    *Config
		op        operator.Type
		req       *requests.Request
		opts      map[string]interface{}
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name:   "authenticate user",
			config: config,
			op:     operator.Authenticate,
			req: &requests.Request{
				User: requests.User{
					Username: tests.TestUser1,
					Email:    tests.TestEmail1,
					Password: tests.TestPwd1,
				},
			},
			want: map[string]interface{}{
				"config": []string{
					"name local_backend", "method local", "realm local",
					"path " + dbPath,
				},
			},
		},
		{
			name:   "authenticate user with invalid password",
			config: config,
			op:     operator.Authenticate,
			req: &requests.Request{
				User: requests.User{
					Username: tests.TestUser1,
					Email:    tests.TestEmail1,
				},
			},
			shouldErr: true,
			err:       errors.ErrBackendLocalAuthFailed.WithArgs("user authentication failed: user password is invalid"),
		},
		{
			name:      "test unknown operator",
			config:    config,
			op:        operator.Unknown,
			shouldErr: true,
			err:       errors.ErrOperatorNotSupported.WithArgs(operator.Unknown),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config:\n%v", tc.config))
			logger := utils.NewLogger()
			b := NewDatabaseBackend(tc.config, logger)
			if err := b.Configure(); err != nil {
				t.Fatalf("configuration error: %v", err)
			}
			if err := b.Validate(); err != nil {
				t.Fatalf("validation error: %v", err)
			}

			err := b.Request(tc.op, tc.req)
			if tests.EvalErrWithLog(t, err, "authenticate", tc.shouldErr, tc.err, msgs) {
				return
			}

			got := make(map[string]interface{})
			got["config"] = strings.Split(b.GetConfig(), "\n")
			tests.EvalObjectsWithLog(t, "user", tc.want, got, msgs)
		})
	}
}
*/
