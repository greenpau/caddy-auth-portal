// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlers

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"path"

	jwtclaims "github.com/greenpau/caddy-auth-jwt/pkg/claims"
	jwtconfig "github.com/greenpau/caddy-auth-jwt/pkg/config"

	"github.com/greenpau/caddy-auth-portal/pkg/cookies"
	"github.com/greenpau/caddy-auth-portal/pkg/ui"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"go.uber.org/zap"
	"time"
)

// ServeLogin returns login page or performs authentication.
func ServeLogin(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	reqID := opts["request_id"].(string)
	log := opts["logger"].(*zap.Logger)
	uiFactory := opts["ui"].(*ui.UserInterfaceFactory)
	authURLPath := opts["auth_url_path"].(string)

	tokenProvider := opts["token_provider"].(*jwtconfig.CommonTokenConfig)

	cookies := opts["cookies"].(*cookies.Cookies)
	redirectToToken := opts["redirect_token_name"].(string)
	authorized := false

	if v, exists := opts["authorized"]; exists {
		authorized = v.(bool)
	}

	if _, exists := opts["status_code"]; !exists {
		opts["status_code"] = 200
	}

	// Remove tokens when authentication failed
	if opts["auth_credentials_found"].(bool) && !opts["authenticated"].(bool) {
		for _, k := range []string{tokenProvider.TokenName} {
			w.Header().Add("Set-Cookie", k+"=delete;"+cookies.GetDeleteAttributes()+" expires=Thu, 01 Jan 1970 00:00:00 GMT")
		}
	}

	// Add non-caching headers
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Create JWT token
	if opts["authenticated"].(bool) && !authorized {
		claims := opts["user_claims"].(*jwtclaims.UserClaims)
		claims.Issuer = utils.GetCurrentURL(r)
		claims.IssuedAt = time.Now().Unix()
		var userToken string
		var tokenError error
		switch tokenProvider.TokenSignMethod {
		case "HS512", "HS384", "HS256":
			userToken, tokenError = claims.GetToken(tokenProvider.TokenSignMethod, []byte(tokenProvider.TokenSecret))
		case "RS512", "RS384", "RS256":
			var privKey *rsa.PrivateKey
			var keyID string
			privKey, keyID, tokenError = tokenProvider.GetPrivateKey()
			if tokenError == nil {
				tokenOpts := make(map[string]interface{})
				tokenOpts["method"] = tokenProvider.TokenSignMethod
				if keyID != "" {
					tokenOpts["kid"] = keyID
				}
				tokenOpts["private_key"] = privKey
				userToken, tokenError = claims.GetSignedToken(tokenOpts)
			}
		default:
			opts["status_code"] = 500
			opts["authenticated"] = false
			opts["message"] = "Internal Server Error"
			log.Error(
				"invalid signing method",
				zap.String("request_id", reqID),
				zap.String("token_sign_method", tokenProvider.TokenSignMethod),
			)
		}
		if tokenError != nil {
			opts["status_code"] = 500
			opts["authenticated"] = false
			opts["message"] = "Internal Server Error"
			log.Warn(
				"token signing error",
				zap.String("request_id", reqID),
				zap.String("error", tokenError.Error()),
			)
		} else {
			if opts["authenticated"].(bool) {
				opts["user_token"] = userToken
				w.Header().Set("Authorization", "Bearer "+userToken)
				w.Header().Set("Set-Cookie", tokenProvider.TokenName+"="+userToken+";"+cookies.GetAttributes())
			}
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
				w.Header().Add("Set-Cookie", redirectToToken+"=delete;"+cookies.GetDeleteAttributes()+" expires=Thu, 01 Jan 1970 00:00:00 GMT")
				w.WriteHeader(302)
				return nil
			}
		}
	}

	// If authenticated, redirect to portal.
	if opts["authenticated"].(bool) {
		w.Header().Set("Location", path.Join(authURLPath, "portal"))
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

	resp.Data["login_options"] = opts["login_options"]
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
		tokenProvider := opts["token_provider"].(*jwtconfig.CommonTokenConfig)
		resp[tokenProvider.TokenName] = opts["user_token"].(string)
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
