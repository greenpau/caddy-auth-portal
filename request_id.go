package portal

import (
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/satori/go.uuid"
	"net/http"
	"strings"
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

// GetSourceAddress returns the IP address of the request.
func GetSourceAddress(r *http.Request) string {
	var addr string
	if r.Header.Get("X-Real-Ip") != "" {
		addr = r.Header.Get("X-Real-Ip")
	} else {
		if r.Header.Get("X-Forwarded-For") != "" {
			addr = r.Header.Get("X-Forwarded-For")
		} else {
			addr = r.RemoteAddr
		}
	}
	if strings.Contains(addr, ",") {
		addr = strings.TrimSpace(addr)
		addr = strings.SplitN(addr, ",", 2)[0]
	}
	if strings.Contains(addr, ":") {
		addr = strings.SplitN(addr, ":", 2)[0]
	}
	return addr
}
