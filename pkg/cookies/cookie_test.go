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

package cookies

import (
	"testing"
)

func TestCookies(t *testing.T) {
	tests := []struct {
		name               string
		cookie             *Cookies
		expRawCookie       string
		expRawDeleteCookie string
	}{
		{
			name: "contoso.com cookie with default path",
			cookie: &Cookies{
				Domain: "contoso.com",
			},
			expRawCookie:       "access_token=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
			expRawDeleteCookie: "access_token=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
		},
		{
			name: "contoso.com cookie with custom path",
			cookie: &Cookies{
				Domain: "contoso.com",
				Path:   "/mydir",
			},
			expRawCookie:       "access_token=foobar; Domain=contoso.com; Path=/mydir; Secure; HttpOnly;",
			expRawDeleteCookie: "access_token=delete; Domain=contoso.com; Path=/mydir; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
		},
		{
			name: "contoso.com cookie custom lifetime",
			cookie: &Cookies{
				Domain:   "contoso.com",
				Lifetime: 900,
			},
			expRawCookie:       "access_token=foobar; Domain=contoso.com; Path=/; Max-Age=900; Secure; HttpOnly;",
			expRawDeleteCookie: "access_token=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
		},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("test %d: %s", i, tc.name)
			rawCookieString := tc.cookie.GetCookie("access_token", "foobar")
			if rawCookieString != tc.expRawCookie {
				t.Errorf("test %d FAIL: cookie value mismatch: %s (received) vs. %s (expected)", i, rawCookieString, tc.expRawCookie)
				return
			}
			rawDeleteCookieString := tc.cookie.GetDeleteCookie("access_token")
			if rawDeleteCookieString != tc.expRawDeleteCookie {
				t.Errorf("test %d FAIL: delete cookie value mismatch: %s (received) vs. %s (expected)", i, rawDeleteCookieString, tc.expRawDeleteCookie)
				return
			}
			t.Logf("test %d PASS: received expected value: %s", i, tc.expRawCookie)
		})
	}
}
