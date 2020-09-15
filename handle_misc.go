package portal

import (
	"net/http"
)

// HandleRedirectUnsupported redirects to unsupported page.
func (m *AuthPortal) HandleRedirectUnsupported(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	w.WriteHeader(404)
	w.Write([]byte(`Feature is unavailable`))
	return nil
}

// HandlePageNotFound returns not found error.
func (m *AuthPortal) HandlePageNotFound(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	w.WriteHeader(404)
	w.Write([]byte(`Not Found - Period`))
	return nil
}

// HandleServeStaticAssets serve static pages.
func (m *AuthPortal) HandleServeStaticAssets(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	w.WriteHeader(404)
	w.Write([]byte(`Not Found - Static Assets`))
	return nil
}
