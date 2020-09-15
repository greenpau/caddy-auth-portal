package portal

import (
	"net/http"
)

// HandleServeStaticAssets serve static pages.
func (m *AuthPortal) HandleServeStaticAssets(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	w.WriteHeader(404)
	w.Write([]byte(`Not Found - Static Assets`))
	return nil
}
