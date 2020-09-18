package handlers

import (
	"net/http"
)

// ServeStaticAssets serves static pages.
func ServeStaticAssets(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	w.WriteHeader(404)
	w.Write([]byte(`Not Found - Static Assets`))
	return nil
}
