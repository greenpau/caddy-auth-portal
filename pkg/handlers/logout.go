package handlers

import (
	"go.uber.org/zap"
	"net/http"
)

// ServeSessionLogoff performs session logout sequence.
func ServeSessionLogoff(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	reqID := opts["request_id"].(string)
	log := opts["logger"].(*zap.Logger)
	authURLPath := opts["auth_url_path"].(string)
	cookieNames := opts["cookie_names"].([]string)

	log.Debug("serve logout redirect",
		zap.String("request_id", reqID),
	)

	for _, cookie := range r.Cookies() {
		for _, cookieName := range cookieNames {
			if cookie.Name != cookieName {
				continue
			}
			w.Header().Add("Set-Cookie", cookieName+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
		}
	}
	w.Header().Set("Location", authURLPath)
	w.WriteHeader(303)
	return nil
}
