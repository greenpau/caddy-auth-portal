package handlers

import (
	"github.com/greenpau/caddy-auth-portal/pkg/cookies"
	"go.uber.org/zap"
	"net/http"
)

// ServeSessionLoginRedirect redirects request to login page.
func ServeSessionLoginRedirect(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	reqID := opts["request_id"].(string)
	log := opts["logger"].(*zap.Logger)
	authURLPath := opts["auth_url_path"].(string)
	cookieNames := opts["cookie_names"].([]string)
	cookies := opts["cookies"].(*cookies.Cookies)

	log.Debug("redirecting to login page",
		zap.String("request_id", reqID),
	)

	for _, k := range cookieNames {
		w.Header().Add("Set-Cookie", k+"=delete;"+cookies.GetDeleteAttributes()+"expires=Thu, 01 Jan 1970 00:00:00 GMT")
	}
	w.Header().Set("Location", authURLPath+"?redirect_url="+r.RequestURI)
	w.WriteHeader(302)
	return nil
}
