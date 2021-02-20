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
	"net/http"
	"path"

	jwtclaims "github.com/greenpau/caddy-auth-jwt/pkg/claims"
	"github.com/greenpau/caddy-auth-portal/pkg/backends"
	"github.com/greenpau/caddy-auth-portal/pkg/cache"
	"github.com/greenpau/caddy-auth-portal/pkg/ui"
	"go.uber.org/zap"
)

// ServeSandbox performs second factore authentication.
func ServeSandbox(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	reqID := opts["request_id"].(string)
	authURLPath := opts["auth_url_path"].(string)
	log := opts["logger"].(*zap.Logger)
	ui := opts["ui"].(*ui.UserInterfaceFactory)
	sandboxID := opts["sandbox_id"].(string)
	sandboxView := opts["sandbox_view"].(string)
	claims := opts["user_claims"].(*jwtclaims.UserClaims)
	sandboxAction := opts["sandbox_action"].(string)

	// Process authentication and registration requests
	if r.Method == "POST" {
		backend := opts["backend"].(*backends.Backend)
		sandboxCache := opts["sandbox_cache"].(*cache.SandboxCache)
		switch sandboxAction {
		case "auth":
			switch sandboxView {
			case "mfa_app_auth":
				formValid := false
				passcodeValid := false

				// Perform form validation
				validateOpts := map[string]interface{}{
					"validate_sandbox_id": sandboxID,
				}
				formData, err := validateMfaAuthTokenForm(r, validateOpts)
				if err != nil {
					log.Warn(
						"form validation failed",
						zap.String("request_id", reqID),
						zap.String("error", err.Error()),
					)
				} else {
					formValid = true
				}

				// Perform passcode validation
				if formValid {
					args := make(map[string]interface{})
					args["username"] = claims.Subject
					args["email"] = claims.Email
					if mfaTokens, err := backend.GetMfaTokens(args); err == nil {
						for _, mfaToken := range mfaTokens {
							err := mfaToken.ValidateCode(formData["passcode"])
							if err == nil {
								passcodeValid = true
								break
							}
						}
					}
				}

				if !passcodeValid {
					log.Warn(
						"app mfa authentication failed",
						zap.String("request_id", reqID),
						zap.String("sandbox_id", sandboxID),
						zap.Any("user", claims),
					)
					// update sandbox cache
					if err := sandboxCache.Jump(sandboxID, "mfa", "denied"); err != nil {
						log.Warn(
							"failed to update sandbox cache with deny",
							zap.String("request_id", reqID),
							zap.String("error", err.Error()),
							zap.Any("user", claims),
							zap.String("sandbox_id", sandboxID),
							zap.String("sandbox_view", sandboxView),
							zap.String("sandbox_action", sandboxAction),
						)
					}
					w.Header().Set("Location", path.Join(authURLPath, "sandbox", sandboxID, "status"))
					w.WriteHeader(302)
					return nil
				}

				log.Info(
					"successful app mfa authentication",
					zap.String("request_id", reqID),
					zap.String("sandbox_id", sandboxID),
					zap.Any("user", claims),
				)
				// update sandbox cache
				if err := sandboxCache.Jump(sandboxID, "mfa", "allowed"); err != nil {
					log.Warn(
						"failed to update sandbox cache with deny",
						zap.String("request_id", reqID),
						zap.String("error", err.Error()),
						zap.Any("user", claims),
						zap.String("sandbox_id", sandboxID),
						zap.String("sandbox_view", sandboxView),
						zap.String("sandbox_action", sandboxAction),
					)
				}

				w.Header().Set("Location", path.Join(authURLPath, "sandbox", sandboxID, "status"))
				w.WriteHeader(302)
				return nil
			default:
				log.Warn(
					"Malformed request",
					zap.String("request_id", reqID),
					zap.String("error", "attempt to POST to unsupported view"),
					zap.String("sandbox_id", sandboxID),
					zap.String("sandbox_view", sandboxView),
					zap.String("sandbox_action", sandboxAction),
				)
				w.Header().Set("Location", authURLPath)
				w.WriteHeader(302)
				return nil
			}
		case "register":
			switch sandboxView {
			case "mfa_app_register":

			default:
				log.Warn(
					"Malformed request",
					zap.String("request_id", reqID),
					zap.String("error", "attempt to POST to unsupported view"),
					zap.String("sandbox_id", sandboxID),
					zap.String("sandbox_view", sandboxView),
					zap.String("sandbox_action", sandboxAction),
				)
				w.Header().Set("Location", authURLPath)
				w.WriteHeader(302)
				return nil
			}
		default:
			log.Warn(
				"Malformed request",
				zap.String("request_id", reqID),
				zap.String("error", "attempt to POST to unsupported action"),
				zap.String("sandbox_id", sandboxID),
				zap.String("sandbox_view", sandboxView),
				zap.String("sandbox_action", sandboxAction),
			)
			w.Header().Set("Location", authURLPath)
			w.WriteHeader(302)
			return nil
		}
	}

	// Display sandbox page
	resp := ui.GetArgs()
	resp.Title = "Multi-Factor Authentication"
	resp.Data["id"] = sandboxID
	resp.Data["view"] = sandboxView
	resp.Data["action"] = sandboxAction

	content, err := ui.Render("sandbox", resp)
	if err != nil {
		log.Error("Failed HTML response rendering", zap.String("request_id", reqID), zap.String("error", err.Error()))
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
