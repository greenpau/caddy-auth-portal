package forms

import (
	"fmt"
	"net/http"
)

func parseRequest(r *http.Request) (map[string]string, error) {
	var reqFields []string
	kv := make(map[string]string)
	var maxBytesLimit int64 = 1000
	var minBytesLimit int64 = 15
	if r.ContentLength > maxBytesLimit {
		return nil, fmt.Errorf("Request payload exceeded the limit of %d bytes: %d", maxBytesLimit, r.ContentLength)
	}
	if r.ContentLength < minBytesLimit {
		return nil, fmt.Errorf("Request payload is too small: %d", r.ContentLength)
	}
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/x-www-form-urlencoded" {
		return nil, fmt.Errorf("Request content type is not application/x-www-form-urlencoded")
	}

	rq := r.FormValue("activity")
	if rq == "" {
		rq = "login"
	}

	switch rq {
	case "login":
		reqFields = []string{"username", "password", "realm"}
	default:
		return nil, fmt.Errorf("request type is unsupported")
	}

	for _, k := range reqFields {
		if v := r.FormValue(k); v != "" {
			kv[k] = v
		}
	}

	if _, exists := kv["realm"]; !exists {
		kv["realm"] = "local"
	}

	return kv, nil
}
