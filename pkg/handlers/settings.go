package handlers

import (
	"net/http"
)

// ServeSettings returns user settings page.
func ServeSettings(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	w.WriteHeader(404)
	w.Write([]byte(`Handle User Profile`))
	return nil
}
