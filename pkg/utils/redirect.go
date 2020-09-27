package utils

import (
	"net/http"
	//	"strings"
)

// GetCurrentURL returns current URL
func GetCurrentURL(r *http.Request) string {
	schema := "https"
	if r.TLS == nil {
		schema = "http"
	}
	return schema + "://" + r.Host + r.URL.Path
}

// GetCurrentBaseURL returns current base URL
func GetCurrentBaseURL(r *http.Request) string {
	schema := "https"
	if r.TLS == nil {
		schema = "http"
	}
	return schema + "://" + r.Host
}
