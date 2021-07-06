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

package authn

import (
	"context"
	// "encoding/json"
	"fmt"
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
	"github.com/greenpau/caddy-auth-portal/pkg/enums/operator"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"github.com/greenpau/go-identity"
	"github.com/greenpau/go-identity/pkg/qr"
	"github.com/greenpau/go-identity/pkg/requests"
	"net/http"
	// "time"
	"go.uber.org/zap"
	"strings"
)

func (p *Authenticator) handleHTTPSandbox(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	var sandboxID, sandboxPartition, sandboxSecret string
	p.disableClientCache(w)
	sandboxEndpoint, err := getEndpoint(r.URL.Path, "/sandbox/")
	if err != nil {
		p.logger.Debug(
			"failed to parse sandbox id from url path",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Error(err),
		)
		return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
	}

	sandboxArr := strings.SplitN(sandboxEndpoint, "/", 2)
	sandboxID = sandboxArr[0]
	if len(sandboxArr) == 2 {
		sandboxPartition = sandboxArr[1]
	}

	// Parse sandbox cookie.
	for _, cookie := range r.Cookies() {
		if cookie.Name != p.cookie.SandboxID {
			continue
		}
		v := strings.TrimSpace(cookie.Value)
		if v == "" {
			continue
		}
		sandboxSecret = v
	}

	if sandboxSecret == "" {
		p.logger.Debug(
			"failed sandbox request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("error", "sandbox secret not found"),
		)
		return p.handleHTTPError(ctx, w, r, rr, http.StatusUnauthorized)
	}

	usr, err := p.sandboxes.Get(sandboxID)
	if err != nil {
		p.logger.Debug(
			"failed to extract cached entry from sandbox",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Error(err),
		)
		return p.handleHTTPError(ctx, w, r, rr, http.StatusUnauthorized)
	}

	if usr.Authenticator.TempSecret != sandboxSecret {
		p.logger.Debug(
			"failed sandbox request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("error", "temp secret mismatch"),
		)
		return p.handleHTTPError(ctx, w, r, rr, http.StatusUnauthorized)
	}

	if usr.Authenticator.TempSessionID != sandboxID {
		p.logger.Debug(
			"failed sandbox request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("error", "sandbox id mismatch"),
		)
		return p.handleHTTPError(ctx, w, r, rr, http.StatusUnauthorized)
	}

	if strings.HasPrefix(sandboxPartition, "mfa-app-barcode/") {
		// Handle App Authenticator barcode.
		sandboxPartition = strings.TrimPrefix(sandboxPartition, "mfa-app-barcode/")
		return p.handleHTTPMfaBarcode(ctx, w, r, sandboxPartition)
	}

	p.logger.Debug(
		"user authorization sandbox",
		zap.String("sandbox_id", sandboxID),
		zap.String("sandbox_secret", sandboxSecret),
		zap.String("sandbox_partition", sandboxPartition),
		zap.Any("checkpoints", usr.Checkpoints),
	)

	// Populate username (sub) and email address (email)
	rr.User.Username = usr.Claims.Subject
	rr.User.Email = usr.Claims.Email

	data, err := p.nextSandboxCheckpoint(r, rr, usr, sandboxPartition)
	if err != nil {
		p.logger.Warn(
			"user authorization checkpoint failed",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Error(err),
		)
		data["error"] = err.Error()
	} else {
		p.logger.Debug(
			"next user authorization checkpoint",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Any("data", data),
		)
	}

	if _, exists := data["authorized"]; exists {
		// The user passed all authorization checkpoints.
		p.logger.Info(
			"user passed all authorization checkpoints",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Any("checkpoints", usr.Checkpoints),
		)
		p.grantAccess(ctx, w, r, rr, usr)
		w.WriteHeader(rr.Response.Code)
		return nil
	}

	// Handle the processing of user views, e.g. app or U2F tokens, etc.
	resp := p.ui.GetArgs()
	resp.Title = "User Authorization"
	if _, exists := data["title"]; exists {
		resp.Title = data["title"].(string)
	}
	resp.BaseURL(rr.Upstream.BasePath)
	resp.Data["id"] = sandboxID
	for k, v := range data {
		resp.Data[k] = v
	}

	content, err := p.ui.Render("sandbox", resp)
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}
	return p.handleHTTPRenderHTML(ctx, w, http.StatusOK, content.Bytes())
}

func (p *Authenticator) nextSandboxCheckpoint(r *http.Request, rr *requests.Request, usr *user.User, action string) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	backend := p.getBackendByRealm(usr.Authenticator.Realm)
	for _, checkpoint := range usr.Checkpoints {
		if checkpoint.Passed {
			continue
		}
		if checkpoint.FailedAttempts > 3 {
			m["title"] = "Authorization Failed"
			m["view"] = "error"
			return m, fmt.Errorf("%v user authorization checkpoint failed", checkpoint.Type)
		}
		switch checkpoint.Type {
		case "mfa":
			if err := backend.Request(operator.GetMfaTokens, rr); err != nil {
				checkpoint.FailedAttempts++
				m["title"] = "Authorization Failed"
				m["view"] = "error"
				return m, err
			}
			var configured, appConfigured, uniConfigured bool
			bundle := rr.Response.Payload.(*identity.MfaTokenBundle)
			for _, token := range bundle.Get() {
				switch token.Type {
				case "totp":
					configured = true
					appConfigured = true
				case "u2f":
					configured = true
					uniConfigured = true
				}
			}
			switch {
			case appConfigured && (action == "mfa-app-auth" || action == ""):
				m["title"] = "Authenticator App"
				m["view"] = "mfa_app_auth"
				m["action"] = "auth"
				if r.Method != "POST" {
					break
				}
				// Handle authenticator app passcode.
				if err := validateMfaAuthTokenForm(r, rr); err != nil {
					m["title"] = "Authorization Failed"
					m["view"] = "error"
					return m, err
				}
				var tokenErrors []string
				var tokenValidated bool
				for _, token := range bundle.Get() {
					if token.Type != "totp" {
						continue
					}
					if err := token.ValidateCode(rr.MfaToken.Passcode); err != nil {
						tokenErrors = append(tokenErrors, err.Error())
						continue
					}
					tokenValidated = true
					break
				}
				if tokenValidated {
					// If validated successfully, continue.
					p.logger.Info(
						"user authorization checkpoint passed",
						zap.String("session_id", rr.Upstream.SessionID),
						zap.String("request_id", rr.ID),
						zap.Int("checkpoint_id", checkpoint.ID),
						zap.String("checkpoint_name", checkpoint.Name),
						zap.String("checkpoint_type", checkpoint.Type),
					)
					checkpoint.Passed = true
					checkpoint.FailedAttempts = 0
				} else {
					if len(tokenErrors) == 0 {
						tokenErrors = append(tokenErrors, "No available application tokens found")
					}
					m["view"] = "error"
					checkpoint.FailedAttempts++
					return m, fmt.Errorf(strings.Join(tokenErrors, "\n"))
				}
			case uniConfigured && (action == "mfa-u2f-auth" || action == ""):
				m["title"] = "Hardware Token"
				m["view"] = "mfa_u2f_auth"
				m["action"] = "auth"
			case !appConfigured && (action == "mfa-app-register"):
				m["title"] = "Authenticator App Registration"
				m["view"] = "mfa_app_register"
				m["action"] = "register"
				if r.Method == "POST" {
					// Perform the validation of the newly registered token.
					if err := validateAddMfaTokenForm(r, rr); err != nil {
						m["view"] = "error"
						checkpoint.FailedAttempts++
						return m, err
					}
					if err := backend.Request(operator.AddMfaToken, rr); err != nil {
						m["view"] = "error"
						checkpoint.FailedAttempts++
						return m, err
					}
					checkpoint.Passed = true
					checkpoint.FailedAttempts = 0
				} else {
					// Display QR code for token registration.
					qr := qr.NewCode()
					qr.Secret = utils.GetRandomStringFromRange(64, 92)
					qr.Type = "totp"
					qr.Label = fmt.Sprintf("AUTHP:%s", usr.Claims.Email)
					qr.Period = 30
					qr.Issuer = "AUTHP"
					qr.Digits = 6
					if err := qr.Build(); err != nil {
						return m, fmt.Errorf("Failed creating QR code: %v", err)
					}
					m["mfa_label"] = qr.Issuer
					m["mfa_comment"] = "My Authentication App"
					m["mfa_email"] = usr.Claims.Email
					m["mfa_type"] = qr.Type
					m["mfa_secret"] = qr.Secret
					m["mfa_period"] = fmt.Sprintf("%d", qr.Period)
					m["mfa_digits"] = fmt.Sprintf("%d", qr.Digits)
					m["code_uri"] = qr.Get()
					m["code_uri_encoded"] = qr.GetEncoded()
				}
			case !uniConfigured && (action == "mfa-u2f-register"):
				m["title"] = "Hardware Token Registration"
				m["view"] = "mfa_u2f_register"
				m["action"] = "register"
			case !configured:
				m["title"] = "Token Registration"
				m["view"] = "mfa_mixed_register"
				m["action"] = "register"
			case appConfigured && uniConfigured:
				m["title"] = "Token Selection"
				m["view"] = "mfa_mixed_auth"
				m["action"] = "auth"
			default:
				checkpoint.FailedAttempts++
				m["title"] = "Bad Request"
				m["view"] = "error"
				return m, fmt.Errorf("Detected unsupported MFA authorization type")
			}
			if !checkpoint.Passed {
				return m, nil
			}
		default:
			checkpoint.FailedAttempts++
			m["title"] = "Bad Request"
			m["view"] = "error"
			return m, fmt.Errorf("Detected unsupported authorization type")
		}
	}
	m["authorized"] = true
	return m, nil
}
