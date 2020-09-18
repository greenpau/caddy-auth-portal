package handlers

import (
	"encoding/json"
	"github.com/greenpau/caddy-auth-jwt"
	"github.com/greenpau/caddy-auth-portal/pkg/cookies"
	"github.com/greenpau/caddy-auth-ui"
	"go.uber.org/zap"
	"net/http"
	"net/url"
)

// ServeLogin returns login page or performs authentication.
func ServeLogin(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	reqID := opts["request_id"].(string)
	log := opts["logger"].(*zap.Logger)
	uiFactory := opts["ui"].(*ui.UserInterfaceFactory)
	authURLPath := opts["auth_url_path"].(string)
	tokenName := opts["token_name"].(string)
	tokenSecret := opts["token_secret"].(string)
	cookies := opts["cookies"].(*cookies.Cookies)
	redirectToToken := opts["redirect_token_name"].(string)

	// If authenticated, redirect to portal
	if opts["authenticated"].(bool) {
		w.Header().Set("Location", authURLPath+"/portal")
		w.WriteHeader(302)
		return nil
	}

	if _, exists := opts["status_code"]; !exists {
		opts["status_code"] = 200
	}

	// Remove tokens when authentication failed
	if opts["auth_credentials_found"].(bool) && !opts["authenticated"].(bool) {
		for _, k := range []string{tokenName} {
			w.Header().Add("Set-Cookie", k+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
		}
	}

	// Add non-caching headers
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Create JWT token
	if opts["authenticated"].(bool) {
		claims := opts["user_claims"].(*jwt.UserClaims)
		userToken, err := claims.GetToken("HS512", []byte(tokenSecret))
		if err != nil {
			opts["status_code"] = 500
			opts["authenticated"] = false
			opts["message"] = "Internal Server Error"
		} else {
			opts["user_token"] = userToken
			w.Header().Set("Authorization", "Bearer "+userToken)
			w.Header().Set("Set-Cookie", tokenName+"="+userToken+";"+cookies.GetAttributes())
		}
	}

	// If the requested content type is JSON, then handle it separately.
	if opts["content_type"].(string) == "application/json" {
		return ServeAPILogin(w, r, opts)
	}

	// Follow redirect URL when authenticated.
	if opts["authenticated"].(bool) {
		if cookie, err := r.Cookie(redirectToToken); err == nil {
			if redirectURL, err := url.Parse(cookie.Value); err == nil {
				log.Debug(
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
		w.Header().Set("Location", authURLPath+"/portal")
		w.WriteHeader(302)
		return nil
	}

	// Display login page
	resp := uiFactory.GetArgs()
	if title, exists := opts["ui_title"]; exists {
		resp.Title = title.(string)
	} else {
		resp.Title = "Sign In"
	}

	if msg, exists := opts["message"]; exists {
		resp.Message = msg.(string)
	}

	content, err := uiFactory.Render("login", resp)
	if err != nil {
		log.Error("Failed HTML response rendering", zap.String("request_id", reqID), zap.String("error", err.Error()))
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

// ServeAPILogin returns authentication response in JSON format.
func ServeAPILogin(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	reqID := opts["request_id"].(string)
	log := opts["logger"].(*zap.Logger)
	resp := make(map[string]interface{})
	if opts["authenticated"].(bool) {
		resp["authenticated"] = true
		tokenName := opts["token_name"].(string)
		tokenValue := opts["user_token"].(string)
		resp[tokenName] = tokenValue
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
		log.Error("Failed JSON response rendering", zap.String("request_id", reqID), zap.String("error", err.Error()))
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
