package portal

import (
	"encoding/json"
	"go.uber.org/zap"
	"net/http"
)

// HandleGeneric returns generic response page.
func (m *AuthPortal) HandleGeneric(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	var title string
	reqID := opts["request_id"].(string)
	flow := opts["flow"].(string)
	switch flow {
	case "not_found":
		title = "Not Found"
	case "unsupported_feature":
		title = "Unsupported Feature"
	default:
		title = "Unsupported Flow"
	}

	// If the requested content type is JSON, then output authenticated message
	if opts["content_type"].(string) == "application/json" {
		resp := make(map[string]interface{})
		resp["message"] = title
		if opts["authenticated"].(bool) {
			resp["authenticated"] = true
		}
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
	resp.Title = title
	resp.Data = make(map[string]interface{})
	resp.Data["go_back_url"] = m.AuthURLPath
	if opts["authenticated"].(bool) {
		resp.Data["authenticated"] = true
		referer := r.Referer()
		if referer != "" {
			resp.Data["go_back_url"] = referer
		}
	} else {
		resp.Data["authenticated"] = false
	}
	content, err := m.uiFactory.Render("generic", resp)
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
