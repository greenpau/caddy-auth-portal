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

package cookie

import (
	"fmt"
	"github.com/greenpau/caddy-auth-portal/internal/tests"
	"testing"
)

func TestFactory(t *testing.T) {
	var testcases = []struct {
		name   string
		config *Config
		// Expected results.
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "default config",
			want: map[string]interface{}{
				"grant":          "access_token=foobar; Path=/; Secure; HttpOnly;",
				"delete":         "access_token=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "contoso.com cookie with default path",
			config: &Config{
				Domain: "contoso.com",
			},
			want: map[string]interface{}{
				"grant":          "access_token=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
				"delete":         "access_token=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "contoso.com cookie with custom path",
			config: &Config{
				Domain: "contoso.com",
				Path:   "/mydir",
			},
			want: map[string]interface{}{
				"grant":          "access_token=foobar; Domain=contoso.com; Path=/mydir; Secure; HttpOnly;",
				"delete":         "access_token=delete; Domain=contoso.com; Path=/mydir; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "contoso.com cookie custom lifetime",
			config: &Config{
				Domain:   "contoso.com",
				Lifetime: 900,
			},
			want: map[string]interface{}{
				"grant":          "access_token=foobar; Domain=contoso.com; Path=/; Max-Age=900; Secure; HttpOnly;",
				"delete":         "access_token=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			cf, err := NewFactory(tc.config)
			if tests.EvalErrWithLog(t, err, "cookie", tc.shouldErr, tc.err, msgs) {
				return
			}
			got := make(map[string]interface{})
			got["grant"] = cf.GetCookie("access_token", "foobar")
			got["delete"] = cf.GetDeleteCookie("access_token")
			got["session_grant"] = cf.GetSessionCookie("foobar")
			got["session_delete"] = cf.GetDeleteSessionCookie()
			tests.EvalObjectsWithLog(t, "cookie", tc.want, got, msgs)
		})
	}
}
