package portal

import (
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/satori/go.uuid"
	"net/http"
)

// GetRequestID returns request ID.
func GetRequestID(r *http.Request) string {
	rawRequestID := caddyhttp.GetVar(r.Context(), "request_id")
	if rawRequestID == nil {
		requestID := uuid.NewV4().String()
		caddyhttp.SetVar(r.Context(), "request_id", requestID)
		return requestID
	}
	return rawRequestID.(string)
}

// GetContentType returns requested content type.
func GetContentType(r *http.Request) string {
	ct := r.Header.Get("Accept")
	if ct == "" {
		ct = "text/html"
	}
	return ct
}
