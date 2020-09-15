package portal

import (
	"encoding/json"
	"go.uber.org/zap"
	"net/http"
)

// HandlePortal returns user identity information.
func (m *AuthPortal) HandlePortal(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	reqID := opts["request_id"].(string)

	if !opts["authenticated"].(bool) {
		w.Header().Set("Location", m.AuthURLPath)
		w.WriteHeader(401)
		return nil
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
