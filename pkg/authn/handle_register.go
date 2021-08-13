// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authn

import (
	"context"
	"github.com/greenpau/caddy-auth-portal/pkg/validators"
	"github.com/greenpau/go-identity/pkg/requests"
	"go.uber.org/zap"
	"net/http"
	"path"
)

func (p *Authenticator) handleHTTPRegister(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	p.disableClientCache(w)
	if rr.Response.Authenticated {
		// Authenticated users are not allowed to register.
		return p.handleHTTPRedirect(ctx, w, r, rr, "/portal")
	}
	if r.Method != "POST" {
		return p.handleHTTPRegisterScreen(ctx, w, r, rr)
	}
	return p.handleHTTPRegisterRequest(ctx, w, r, rr)
}

func (p *Authenticator) handleHTTPRegisterScreen(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, false, "")
}

func (p *Authenticator) handleHTTPRegisterScreenWithMessage(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, registered bool, msg string) error {
	code := http.StatusOK
	if msg != "" {
		code = http.StatusBadRequest
	}
	if p.UserRegistrationConfig.Dropbox == "" {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusServiceUnavailable)
	}
	if p.registrar == nil {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusFailedDependency)
	}
	resp := p.ui.GetArgs()
	resp.BaseURL(rr.Upstream.BasePath)
	if p.UserRegistrationConfig.Title == "" {
		resp.Title = "Sign Up"
	} else {
		resp.Title = p.UserRegistrationConfig.Title
	}
	if p.UserRegistrationConfig.RequireAcceptTerms {
		resp.Data["require_accept_terms"] = true
	}
	if p.UserRegistrationConfig.Code != "" {
		resp.Data["require_registration_code"] = true
	}
	if p.UserRegistrationConfig.TermsConditionsLink != "" {
		resp.Data["terms_conditions_link"] = p.UserRegistrationConfig.TermsConditionsLink
	} else {
		resp.Data["terms_conditions_link"] = path.Join(rr.Upstream.BasePath, "/terms-and-conditions")
	}
	if p.UserRegistrationConfig.PrivacyPolicyLink != "" {
		resp.Data["privacy_policy_link"] = p.UserRegistrationConfig.PrivacyPolicyLink
	} else {
		resp.Data["privacy_policy_link"] = path.Join(rr.Upstream.BasePath, "/privacy-policy")
	}

	resp.Data["username_validate_pattern"] = p.registrar.GetUsernamePolicyRegex()
	resp.Data["username_validate_title"] = p.registrar.GetUsernamePolicySummary()
	resp.Data["password_validate_pattern"] = p.registrar.GetPasswordPolicyRegex()
	resp.Data["password_validate_title"] = p.registrar.GetPasswordPolicySummary()

	if registered {
		resp.Title = "Thank you!"
		resp.Data["registered"] = registered
	}
	if msg != "" {
		resp.Message = msg
	}
	content, err := p.ui.Render("register", resp)
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}
	return p.handleHTTPRenderHTML(ctx, w, code, content.Bytes())
}

func (p *Authenticator) handleHTTPRegisterRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	var message string
	var maxBytesLimit int64 = 1000
	var minBytesLimit int64 = 15
	var userHandle, userMail, userSecret, userSecretConfirm, userCode string
	var violations []string
	var userAccept, validUserRegistration bool
	validUserRegistration = true

	if r.ContentLength > maxBytesLimit || r.ContentLength < minBytesLimit {
		violations = append(violations, "payload size")
	}
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		violations = append(violations, "content type")
	}

	if len(violations) > 0 {
		message = "Registration request is non compliant"
		p.logger.Warn(
			message,
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Int64("min_size", minBytesLimit),
			zap.Int64("max_size", maxBytesLimit),
			zap.String("content_type", r.Header.Get("Content-Type")),
			zap.Int64("size", r.ContentLength),
			zap.Strings("violations", violations),
		)
		return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, false, message)
	}

	if err := r.ParseForm(); err != nil {
		p.logger.Warn(
			"failed parsing submitted registration form",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("error", err.Error()),
		)
		message = "Failed processing the registration form"
		validUserRegistration = false
	} else {
		for k, v := range r.Form {
			switch k {
			case "username":
				userHandle = v[0]
			case "password":
				userSecret = v[0]
			case "password_confirm":
				userSecretConfirm = v[0]
			case "email":
				userMail = v[0]
			case "code":
				userCode = v[0]
			case "accept_terms":
				if v[0] == "on" {
					userAccept = true
				}
			case "submit":
			default:
				p.logger.Warn(
					"registration request payload contains unsupported field",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("field_name", k),
				)
				message = "Failed processing the registration form due to unsupported field"
				validUserRegistration = false
				break
			}
		}
	}

	if validUserRegistration {
		// Inspect registration values.
		if userSecret != userSecretConfirm {
			validUserRegistration = false
			message = "Failed processing the registration form due to mismatched passwords"
		}

		if p.UserRegistrationConfig.Code != "" {
			if userCode != p.UserRegistrationConfig.Code {
				validUserRegistration = false
				message = "Failed processing the registration form due to invalid verification code"
			}
		}

		if p.UserRegistrationConfig.RequireAcceptTerms {
			if !userAccept {
				validUserRegistration = false
				message = "Failed processing the registration form due to the failure to accept terms and conditions"
			}
		}

		for _, k := range []string{"username", "password", "email"} {
			if !validUserRegistration {
				break
			}
			switch k {
			case "username":
				handleOpts := make(map[string]interface{})
				if err := validators.ValidateUserInput("handle", userHandle, handleOpts); err != nil {
					validUserRegistration = false
					message = "Failed processing the registration form due " + err.Error()
				}
			case "password":
				secretOpts := make(map[string]interface{})
				if err := validators.ValidateUserInput("secret", userSecret, secretOpts); err != nil {
					validUserRegistration = false
					message = "Failed processing the registration form due " + err.Error()
				}
			case "email":
				emailOpts := make(map[string]interface{})
				if p.UserRegistrationConfig.RequireDomainMailRecord {
					emailOpts["check_domain_mx"] = true
				}
				if err := validators.ValidateUserInput(k, userMail, emailOpts); err != nil {
					validUserRegistration = false
					message = "Failed processing the registration form due " + err.Error()
				}
			}
		}
	}

	if validUserRegistration {
		// Contact registration backend.
		req := &requests.Request{
			User: requests.User{
				Username: userHandle,
				Password: userSecret,
				Email:    userMail,
				Roles:    []string{"registered"},
			},
		}
		if err := p.registrar.AddUser(req); err != nil {
			p.logger.Warn(
				"registration request backend erred",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("error", err.Error()),
			)
			message = "Failed processing the registration request"
			message = err.Error()
			validUserRegistration = false
		}
	}

	if !validUserRegistration {
		p.logger.Warn(
			"failed registration",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("error", message),
		)
		return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, false, message)
	}

	p.logger.Info("Successful user registration",
		zap.String("session_id", rr.Upstream.SessionID),
		zap.String("request_id", rr.ID),
		zap.String("username", userHandle),
		zap.String("email", userMail),
	)
	return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, true, message)
}
