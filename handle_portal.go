package portal

import (
	"encoding/json"
	"go.uber.org/zap"
	"net/http"
	"net/url"
)

// HandlePortal returns user identity information.
func (m *AuthPortal) HandlePortal(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	reqID := opts["request_id"].(string)

	if !opts["authenticated"].(bool) {
		w.Header().Set("Location", m.AuthURLPath)
		w.WriteHeader(302)
		return nil
	}

	if cookie, err := r.Cookie(redirectToToken); err == nil {
		if redirectURL, err := url.Parse(cookie.Value); err == nil {
			m.logger.Debug(
				"Cookie-based redirect",
				zap.String("request_id", reqID),
				zap.String("redirect_url", redirectURL.String()),
			)
			w.Header().Set("Location", redirectURL.String())
			w.Header().Add("Set-Cookie", redirectToToken+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
			w.WriteHeader(303)
			return nil
		}
	}

	// If the requested content type is JSON, then output authenticated message.
	if opts["content_type"].(string) == "application/json" {
		resp := make(map[string]interface{})
		resp["authenticated"] = true
		payload, err := json.Marshal(resp)
		if err != nil {
			m.logger.Error("Failed JSON response rendering", zap.String("request_id", reqID), zap.String("error", err.Error()))
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(500)
			w.Write([]byte(`Internal Server Error`))
			return err
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(payload)
		return nil
	}

	// Display main authentication portal page
	resp := m.uiFactory.GetArgs()
	resp.Title = "Welcome"
	content, err := m.uiFactory.Render("portal", resp)
	if err != nil {
		m.logger.Error("Failed HTML response rendering", zap.String("request_id", reqID), zap.String("error", err.Error()))
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(500)
		w.Write([]byte(`Internal Server Error`))
		return err
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write(content.Bytes())
	return nil
}
