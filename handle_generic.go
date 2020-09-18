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
	statusCode := 200
	switch flow {
	case "not_found":
		title = "Not Found"
		statusCode = 404
	case "unsupported_feature":
		title = "Unsupported Feature"
		statusCode = 404
	case "policy_violation":
		title = "Policy Violation"
		statusCode = 400
	case "internal_server_error":
		title = "Internal Server Error"
		statusCode = 500
	default:
		title = "Unsupported Flow"
		statusCode = 400
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
		w.WriteHeader(statusCode)
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
	w.WriteHeader(statusCode)
	w.Write(content.Bytes())
	return nil
}
