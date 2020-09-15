package portal

import (
	"net/http"
)

// HandleSessionLogoff performs session logout sequence.
func (m *AuthPortal) HandleSessionLogoff(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	for _, k := range []string{redirectToToken, m.TokenProvider.TokenName} {
		w.Header().Add("Set-Cookie", k+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
	}
	w.Header().Set("Location", m.AuthURLPath)
	w.WriteHeader(303)
	return nil
}
