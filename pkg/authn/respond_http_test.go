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
		reqUrl := url.URL{
			Scheme:   "https",
			Host:     "foo.bar",
			Path:     "/myPage",
			RawQuery: "redirect_url=https%3A%2F%2Ffoo.bar%2Fredir%3Flogin_hint%3Dmy%40email.com",
		}
		r := http.Request{URL: &reqUrl, Method: "GET"}
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
