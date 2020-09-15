package portal

import (
	"encoding/json"
	jwt "github.com/greenpau/caddy-auth-jwt"
	"go.uber.org/zap"
	"net/http"
)

// HandleWhoami returns portal page for authenticated users.
func (m *AuthPortal) HandleWhoami(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	reqID := opts["request_id"].(string)

	if !opts["authenticated"].(bool) {
		w.Header().Set("Location", m.AuthURLPath)
		w.WriteHeader(401)
		return nil
	}

	claims := opts["user_claims"].(*jwt.UserClaims)
	// If the requested content type is JSON, then output authenticated message
	if opts["content_type"].(string) == "application/json" {
		payload, err := json.Marshal(claims)
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
	resp.Title = "User Identity"
	tokenMap := claims.AsMap()
	tokenMap["authenticated"] = true
	prettyTokenMap, err := json.MarshalIndent(tokenMap, "", "  ")
	if err != nil {
		m.logger.Error("Failed token map rendering", zap.String("request_id", reqID), zap.String("error", err.Error()))
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(500)
		w.Write([]byte(`Internal Server Error`))
		return err
	}
	resp.Data["token"] = string(prettyTokenMap)

	content, err := m.uiFactory.Render("whoami", resp)
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
