package portal

import (
	"net/http"
)

// HandleProfile returns user profile page.
func (m *AuthPortal) HandleProfile(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	w.WriteHeader(404)
	w.Write([]byte(`Handle User Profile`))
	return nil
}
