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

package backends

import (
	"fmt"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/ldap"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/local"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/oauth2"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/saml"
	"github.com/greenpau/caddy-auth-portal/pkg/enums/operator"
	"github.com/greenpau/caddy-auth-portal/pkg/errors"
	"github.com/greenpau/go-identity/pkg/requests"
	"strings"

	"github.com/greenpau/caddy-auth-portal/internal/tests"
	logutils "github.com/greenpau/caddy-authorize/pkg/utils/log"
	"go.uber.org/zap"
	"testing"
)

func TestBackendConfig(t *testing.T) {
	testcases := []struct {
		name          string
		config        *Config
		fromConfigMap bool
		configMap     map[string]interface{}
		disableLogger bool
		want          map[string]interface{}
		shouldErr     bool
		err           error
	}{
		{
			name: "test ldap backend",
			config: &Config{
				Ldap: &ldap.Config{
					Name:   "ldap_backend",
					Method: "ldap",
					Realm:  "contoso.com",
					Servers: []ldap.AuthServer{
						ldap.AuthServer{
							Address:          "ldaps://ldaps.contoso.com",
							IgnoreCertErrors: true,
							Timeout:          0,
						},
					},
					BindUsername: "CN=authzsvc,OU=Service Accounts,OU=Administrative Accounts,DC=CONTOSO,DC=COM",
					BindPassword: "P@ssW0rd123",
					Attributes: ldap.UserAttributes{
						Name:     "givenName",
						Surname:  "sn",
						Username: "sAMAccountName",
						MemberOf: "memberOf",
						Email:    "mail",
					},
					SearchBaseDN:     "DC=CONTOSO,DC=COM",
					SearchUserFilter: `(&(|(sAMAccountName=%s)(mail=%s))(objectclass=user))`,
					Groups: []ldap.UserGroup{
						ldap.UserGroup{
							GroupDN: "CN=Admins,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
							Roles:   []string{"admin"},
						},
						ldap.UserGroup{
							GroupDN: "CN=Editors,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
							Roles:   []string{"editor"},
						}, ldap.UserGroup{
							GroupDN: "CN=Viewers,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
							Roles:   []string{"viewer"},
						},
					},
					TrustedAuthorities: []string{},
				},
			},
			want: map[string]interface{}{
				"realm":       "contoso.com",
				"name":        "ldap_backend",
				"method":      "ldap",
				"method_type": "LDAP",
				"config": []string{
					"name ldap_backend",
					"method ldap",
					"realm contoso.com",
					"",
				},
			},
		},
		{
			name: "test local backend",
			config: &Config{
				Local: &local.Config{
					Name:   "local_backend",
					Method: "local",
					Realm:  "local",
					Path:   "assets/conf/local/auth/user_db.json",
				},
			},
			want: map[string]interface{}{
				"name":        "local_backend",
				"method":      "local",
				"realm":       "local",
				"method_type": "Local",
				"config": []string{
					"name local_backend",
					"method local",
					"realm local",
					"path assets/conf/local/auth/user_db.json",
				},
			},
		},
		{
			name: "test saml backend",
			config: &Config{
				Saml: &saml.Config{
					Name:     "saml_backend",
					Method:   "saml",
					Realm:    "azure",
					Provider: "azure",
				},
			},
			want: map[string]interface{}{
				"name":        "saml_backend",
				"method":      "saml",
				"realm":       "azure",
				"method_type": "SAML",
				"config": []string{
					"name saml_backend",
					"method saml",
					"realm azure",
					"provider azure",
				},
			},
		},
		{
			name: "test oauth2 backend",
			config: &Config{
				OAuth2: &oauth2.Config{
					Name:     "oauth2_backend",
					Method:   "oauth2",
					Realm:    "google",
					Provider: "google",
				},
			},
			want: map[string]interface{}{
				"name":        "oauth2_backend",
				"method":      "oauth2",
				"realm":       "google",
				"method_type": "OAuth 2.0",
				"config": []string{
					"name oauth2_backend",
					"method oauth2",
					"realm google",
					"provider google",
				},
			},
		},
		{
			name:          "test without logger",
			disableLogger: true,
			config: &Config{
				Local: &local.Config{
					Method: "local",
				},
			},
			shouldErr: true,
			err:       errors.ErrBackendConfigureLoggerNotFound,
		},
		{
			name: "test auth method mismatch",
			config: &Config{
				Local: &local.Config{
					Method: "oauth2",
				},
			},
			shouldErr: true,
			err:       errors.ErrBackendConfigureInvalidMethod.WithArgs("local", "oauth2"),
		},
		{
			name:      "test empty config",
			config:    &Config{},
			shouldErr: true,
			err:       errors.ErrBackendConfigureEmptyConfig,
		},
		{
			name: "test multiple auth methods",
			config: &Config{
				Local: &local.Config{
					Method: "local",
				},
				OAuth2: &oauth2.Config{
					Method: "oauth2",
				},
			},
			shouldErr: true,
			err:       errors.ErrBackendConfigureMultipleMethods.WithArgs([]string{"local", "oauth2"}),
		},
		{
			name:          "test new config with local backend",
			fromConfigMap: true,
			configMap: map[string]interface{}{
				"name":   "local_backend",
				"method": "local",
				"realm":  "local",
				"path":   "assets/conf/local/auth/user_db.json",
			},
			want: map[string]interface{}{
				"name":        "local_backend",
				"method":      "local",
				"realm":       "local",
				"method_type": "Local",
				"config": []string{
					"name local_backend",
					"method local",
					"realm local",
					"path assets/conf/local/auth/user_db.json",
				},
			},
		},
		{
			name:          "test new config with ldap backend",
			fromConfigMap: true,
			configMap: map[string]interface{}{
				"name":   "ldap_backend",
				"method": "ldap",
				"realm":  "contoso.com",
			},
			want: map[string]interface{}{
				"name":        "ldap_backend",
				"method":      "ldap",
				"realm":       "contoso.com",
				"method_type": "LDAP",
				"config": []string{
					"name ldap_backend",
					"method ldap",
					"realm contoso.com",
					"",
				},
			},
		},
		{
			name:          "test new config with saml backend",
			fromConfigMap: true,
			configMap: map[string]interface{}{
				"name":     "saml_backend",
				"method":   "saml",
				"realm":    "azure",
				"provider": "azure",
			},
			want: map[string]interface{}{
				"name":        "saml_backend",
				"method":      "saml",
				"realm":       "azure",
				"method_type": "SAML",
				"config": []string{
					"name saml_backend",
					"method saml",
					"realm azure",
					"provider azure",
				},
			},
		},
		{
			name:          "test new config with saml backend",
			fromConfigMap: true,
			configMap: map[string]interface{}{
				"name":     "oauth2_backend",
				"method":   "oauth2",
				"realm":    "google",
				"provider": "google",
			},
			want: map[string]interface{}{
				"name":        "oauth2_backend",
				"method":      "oauth2",
				"realm":       "google",
				"method_type": "OAuth 2.0",
				"config": []string{
					"name oauth2_backend",
					"method oauth2",
					"realm google",
					"provider google",
				},
			},
		},
		{
			name:          "test new config with nil map",
			fromConfigMap: true,
			shouldErr:     true,
			err: errors.ErrBackendNewConfig.WithArgs(
				map[string]interface{}{}, "invalid config",
			),
		},
		{
			name:          "test new config with misspelled method map",
			fromConfigMap: true,
			configMap: map[string]interface{}{
				"meth0d": "local",
			},
			shouldErr: true,
			err: errors.ErrBackendNewConfig.WithArgs(
				map[string]interface{}{"meth0d": "local"},
				"auth method not found",
			),
		},
		{
			name:          "test new config with invalid auth method map",
			fromConfigMap: true,
			configMap: map[string]interface{}{
				"method": "foobar",
			},
			shouldErr: true,
			err: errors.ErrBackendNewConfigInvalidAuthMethod.WithArgs(
				map[string]interface{}{"method": "foobar"},
			),
		},
		{
			name:          "test new local config with invalid map",
			fromConfigMap: true,
			configMap: map[string]interface{}{
				"method": "local",
				"name":   123,
			},
			shouldErr: true,
			err: errors.ErrBackendNewConfig.WithArgs(
				map[string]interface{}{"method": "local", "name": 123},
				"json: cannot unmarshal number into Go struct field Config.name of type string",
			),
		},
		{
			name:          "test new ldap config with invalid map",
			fromConfigMap: true,
			configMap: map[string]interface{}{
				"method": "ldap",
				"name":   123,
			},
			shouldErr: true,
			err: errors.ErrBackendNewConfig.WithArgs(
				map[string]interface{}{"method": "ldap", "name": 123},
				"json: cannot unmarshal number into Go struct field Config.name of type string",
			),
		},
		{
			name:          "test new saml config with invalid map",
			fromConfigMap: true,
			configMap: map[string]interface{}{
				"method": "saml",
				"name":   123,
			},
			shouldErr: true,
			err: errors.ErrBackendNewConfig.WithArgs(
				map[string]interface{}{"method": "saml", "name": 123},
				"json: cannot unmarshal number into Go struct field Config.name of type string",
			),
		},
		{
			name:          "test new oauth2 config with invalid map",
			fromConfigMap: true,
			configMap: map[string]interface{}{
				"method": "oauth2",
				"name":   123,
			},
			shouldErr: true,
			err: errors.ErrBackendNewConfig.WithArgs(
				map[string]interface{}{"method": "oauth2", "name": 123},
				"json: cannot unmarshal number into Go struct field Config.name of type string",
			),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var logger *zap.Logger
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config:\n%v", tc.config))
			if !tc.disableLogger {
				logger = logutils.NewLogger()
			}

			if tc.fromConfigMap {
				cfg, err := NewConfig(tc.configMap)
				if tests.EvalErrWithLog(t, err, tc.config, tc.shouldErr, tc.err, msgs) {
					return
				}
				tc.config = cfg
			}

			b, err := NewBackend(tc.config, logger, nil)
			if tests.EvalErrWithLog(t, err, tc.config, tc.shouldErr, tc.err, msgs) {
				return
			}
			got := make(map[string]interface{})
			got["realm"] = b.GetRealm()
			got["name"] = b.GetName()
			got["method"] = b.GetMethod()
			got["method_type"] = b.Method.String()
			got["config"] = strings.Split(b.GetConfig(), "\n")
			tests.EvalObjectsWithLog(t, "config", tc.want, got, msgs)
		})
	}
}

func TestAuthMethodType(t *testing.T) {
	testcases := []struct {
		name       string
		methodType AuthMethodType
		want       map[string]interface{}
		shouldErr  bool
		err        error
	}{
		{
			name:       "test unknown auth type",
			methodType: 0,
			want:       map[string]interface{}{"method_type": "Unknown"},
		},
		{
			name:       "test local auth type",
			methodType: 1,
			want:       map[string]interface{}{"method_type": "Local"},
		},
		{
			name:       "test ldap auth type",
			methodType: 2,
			want:       map[string]interface{}{"method_type": "LDAP"},
		},
		{
			name:       "test saml auth type",
			methodType: 3,
			want:       map[string]interface{}{"method_type": "SAML"},
		},
		{
			name:       "test oauth2 auth type",
			methodType: 4,
			want:       map[string]interface{}{"method_type": "OAuth 2.0"},
		},
		{
			name:       "test random auth type",
			methodType: 100,
			want:       map[string]interface{}{"method_type": "AuthMethodType(100)"},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var method AuthMethodType
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("method:\n%d", tc.methodType))
			got := make(map[string]interface{})
			method = tc.methodType
			got["method_type"] = method.String()
			tests.EvalObjectsWithLog(t, "config", tc.want, got, msgs)
		})
	}
}

func TestBackend(t *testing.T) {
	testcases := []struct {
		name      string
		config    *Config
		op        operator.Type
		req       *requests.Request
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "test local backend",
			config: &Config{
				Local: &local.Config{
					Name:   "local_backend",
					Method: "local",
					Realm:  "local",
					Path:   "../../assets/conf/local/auth/user_db.json",
				},
			},
			op: operator.GetPublicKeys,
			req: &requests.Request{
				User: requests.User{
					Username: "webadmin",
					Email:    "webadmin@localdomain.local",
				},
				Key: requests.Key{
					Usage: "ssh",
				},
			},
			want: map[string]interface{}{
				"name":        "local_backend",
				"method":      "local",
				"realm":       "local",
				"method_type": "Local",
				"config": []string{
					"name local_backend",
					"method local",
					"realm local",
					"path ../../assets/conf/local/auth/user_db.json",
				},
			},
		},
		{
			name: "test unknown operator",
			config: &Config{
				Local: &local.Config{
					Name:   "local_backend",
					Method: "local",
					Realm:  "local",
					Path:   "../../assets/conf/local/auth/user_db.json",
				},
			},
			op:        operator.Unknown,
			req:       &requests.Request{},
			shouldErr: true,
			err:       errors.ErrOperatorNotSupported.WithArgs(operator.Unknown),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config:\n%v", tc.config))
			logger := logutils.NewLogger()
			b, err := NewBackend(tc.config, logger, nil)
			if err != nil {
				t.Fatalf("initialization error: %v", err)
			}

			if err := b.Configure(); err != nil {
				t.Fatalf("configuration error: %v", err)
			}

			if err := b.Validate(); err != nil {
				t.Fatalf("validation error: %v", err)
			}

			err = b.Request(tc.op, tc.req)
			if tests.EvalErrWithLog(t, err, "request", tc.shouldErr, tc.err, msgs) {
				return
			}

			/*
				got := make(map[string]interface{})
				got["realm"] = b.GetRealm()
				got["name"] = b.GetName()
				got["method"] = b.GetMethod()
				got["method_type"] = b.Method.String()
				got["config"] = strings.Split(b.GetConfig(), "\n")
				tests.EvalObjectsWithLog(t, "config", tc.want, got, msgs)
			*/
		})
	}
}
