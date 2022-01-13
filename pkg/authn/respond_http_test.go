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
	"context"
	"github.com/greenpau/caddy-auth-portal/internal/tests"
	"github.com/greenpau/caddy-auth-portal/pkg/cookie"
	"github.com/greenpau/go-identity/pkg/requests"
	"go.uber.org/zap"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type mockResponseWriter struct{}

func (w *mockResponseWriter) Header() http.Header {
	return http.Header{}
}

func (w *mockResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (w *mockResponseWriter) WriteHeader(int) {}

func TestInjectRedirectURL(t *testing.T) {

	t.Run("Strips login hint from redirect URL if present", func(t *testing.T) {
		reqURL := url.URL{
			Scheme:   "https",
			Host:     "foo.bar",
			Path:     "/myPage",
			RawQuery: "redirect_url=https%3A%2F%2Ffoo.bar%2Fredir%3Flogin_hint%3Dmy%40email.com",
		}
		r := http.Request{URL: &reqURL, Method: "GET"}
		f, _ := cookie.NewFactory(nil)
		p := Authenticator{
			Name:   "someAuthenticator",
			logger: zap.L(),
			cookie: f,
		}
		request := requests.NewRequest()

		p.injectRedirectURL(context.Background(), &mockResponseWriter{}, &r, request)

		cookieParts := strings.Split(request.Response.RedirectURL, ";")
		tests.EvalObjectsWithLog(t, "redirect url", "AUTHP_REDIRECT_URL=https://foo.bar/redir", cookieParts[0], []string{})

	})

}
