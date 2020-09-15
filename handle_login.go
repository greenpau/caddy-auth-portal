package portal

import (
	"encoding/json"
	jwt "github.com/greenpau/caddy-auth-jwt"
	"go.uber.org/zap"
	"net/http"
	"net/url"
)

// HandleLogin returns login page or performs authentication.
func (m *AuthPortal) HandleLogin(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	reqID := opts["request_id"].(string)

	if opts["authenticated"].(bool) {
		w.Header().Set("Location", m.AuthURLPath+"/portal")
		w.WriteHeader(302)
		return nil
	}

	// Authenticating the request
	if credentials, err := parseCredentials(r); err == nil {
		if credentials != nil {
			opts["auth_credentials_found"] = true
			for _, backend := range m.Backends {
				if backend.GetRealm() != credentials["realm"] {
					continue
				}
				opts["auth_backend_found"] = true
				if claims, code, err := backend.Authenticate(reqID, credentials); err != nil {
					opts["message"] = "Authentication failed"
					opts["status_code"] = code
					m.logger.Warn("Authentication failed",
						zap.String("request_id", reqID),
						zap.String("error", err.Error()),
					)
				} else {
					opts["user_claims"] = claims
					opts["authenticated"] = true
					opts["status_code"] = 200
					m.logger.Debug("Authentication succeeded",
						zap.String("request_id", reqID),
						zap.Any("user", claims),
					)
				}
			}
			if !opts["auth_backend_found"].(bool) {
				opts["status_code"] = 500
				m.logger.Warn("Authentication failed",
					zap.String("request_id", reqID),
					zap.String("error", "no matching auth backend found"),
				)
			}
		}
	} else {
		opts["message"] = "Authentication failed"
		opts["status_code"] = 400
		m.logger.Warn("Authentication failed",
			zap.String("request_id", reqID),
			zap.String("error", err.Error()),
		)
	}

	if _, exists := opts["status_code"]; !exists {
		opts["status_code"] = 200
	}

	// Remove tokens when authentication failed
	if opts["auth_credentials_found"].(bool) && !opts["authenticated"].(bool) {
		for _, k := range []string{m.TokenProvider.TokenName} {
			w.Header().Add("Set-Cookie", k+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
		}
	}

	// Add non-caching headers
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Create JWT token
	if opts["authenticated"].(bool) {
		claims := opts["user_claims"].(*jwt.UserClaims)
		userToken, err := claims.GetToken("HS512", []byte(m.TokenProvider.TokenSecret))
		if err != nil {
			opts["status_code"] = 500
			opts["authenticated"] = false
			opts["message"] = "Internal Server Error"
		} else {
			opts["user_token"] = userToken
			w.Header().Set("Authorization", "Bearer "+userToken)
			w.Header().Set("Set-Cookie", m.TokenProvider.TokenName+"="+userToken+";"+m.Cookies.GetAttributes())
		}
	}

	// If the requested content type is JSON, then handle it separately.
	if opts["content_type"].(string) == "application/json" {
		return m.HandleAPILogin(w, r, opts)
	}

	// Follow redirect URL when authenticated.
	if opts["authenticated"].(bool) {
		if cookie, err := r.Cookie(redirectToToken); err == nil {
			if redirectURL, err := url.Parse(cookie.Value); err == nil {
				m.logger.Debug(
					"detected cookie-based redirect",
					zap.String("request_id", reqID),
					zap.String("redirect_url", redirectURL.String()),
				)
				w.Header().Set("Location", redirectURL.String())
				w.Header().Add("Set-Cookie", redirectToToken+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
				w.WriteHeader(302)
				return nil
			}
		}
	}

	// If authenticated, redirect to portal.
	if opts["authenticated"].(bool) {
		w.Header().Set("Location", m.AuthURLPath+"/portal")
		w.WriteHeader(302)
		return nil
	}

	// Display login page
	resp := m.uiFactory.GetArgs()
	if m.UserInterface.Title == "" {
		resp.Title = "Sign In"
	} else {
		resp.Title = m.UserInterface.Title
	}
	if msg, exists := opts["message"]; exists {
		resp.Message = msg.(string)
	}

	content, err := m.uiFactory.Render("login", resp)
	if err != nil {
		m.logger.Error("Failed HTML response rendering", zap.String("request_id", reqID), zap.String("error", err.Error()))
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(500)
		w.Write([]byte(`Internal Server Error`))
		return err
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(opts["status_code"].(int))
	w.Write(content.Bytes())
	return nil
}

// HandleAPILogin returns authentication response in JSON format.
func (m *AuthPortal) HandleAPILogin(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	reqID := opts["request_id"].(string)
	resp := make(map[string]interface{})
	if opts["authenticated"].(bool) {
		resp["authenticated"] = true
		resp[m.TokenProvider.TokenName] = opts["user_token"].(string)
	} else {
		resp["authenticated"] = false
		if opts["auth_credentials_found"].(bool) {
			resp["error"] = true
			if msg, exists := opts["message"]; exists {
				resp["message"] = msg
			} else {
				resp["message"] = "authentication failed"
			}
		} else {
			resp["message"] = "authentication credentials required"
		}
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
	w.WriteHeader(opts["status_code"].(int))
	w.Write(payload)
	return nil
}
