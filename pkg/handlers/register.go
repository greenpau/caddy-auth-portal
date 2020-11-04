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
	"github.com/greenpau/caddy-auth-portal/pkg/registration"
	"github.com/greenpau/caddy-auth-portal/pkg/ui"
	"github.com/greenpau/caddy-auth-portal/pkg/validators"
	"github.com/greenpau/go-identity"
	"go.uber.org/zap"
	"net/http"
)

// ServeRegister returns registration page.
func ServeRegister(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	reqID := opts["request_id"].(string)
	log := opts["logger"].(*zap.Logger)
	uiFactory := opts["ui"].(*ui.UserInterfaceFactory)
	authURLPath := opts["auth_url_path"].(string)
	registration := opts["registration"].(*registration.Registration)
	registrationDatabase := opts["registration_db"].(*identity.Database)

	var message string
	var maxBytesLimit int64 = 1000
	var minBytesLimit int64 = 15
	var userHandle, userMail, userSecret, userSecretConfirm, userCode string
	var userAccept, validUserRegistration bool

	if opts["authenticated"].(bool) {
		w.Header().Set("Location", authURLPath)
		w.WriteHeader(302)
		return nil
	}

	if registration.Dropbox == "" {
		opts["flow"] = "unsupported_feature"
		return ServeGeneric(w, r, opts)
	}

	if registrationDatabase == nil {
		opts["flow"] = "internal_server_error"
		return ServeGeneric(w, r, opts)
	}

	if msg, exists := opts["message"]; exists {
		message = msg.(string)
	}

	// Add non-caching headers
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// If the requested content type is JSON, then handle it separately.
	if opts["content_type"].(string) == "application/json" {
		opts["flow"] = "unsupported_feature"
		return ServeGeneric(w, r, opts)
	}

	// Handle registration submission
	if r.Method == "POST" {
		validUserRegistration = true
		if r.ContentLength > maxBytesLimit || r.ContentLength < minBytesLimit {
			log.Warn(
				"request payload violated limits",
				zap.String("request_id", reqID),
				zap.Int64("min_size_limit", minBytesLimit),
				zap.Int64("max_size_limit", maxBytesLimit),
				zap.Int64("request_size", r.ContentLength),
			)
			opts["flow"] = "policy_violation"
			return ServeGeneric(w, r, opts)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			log.Warn(
				"request payload violated content type",
				zap.String("request_id", reqID),
				zap.String("request_content_type", r.Header.Get("Content-Type")),
				zap.String("expected_content_type", "application/x-www-form-urlencoded"),
			)
			opts["flow"] = "policy_violation"
			return ServeGeneric(w, r, opts)
		}

		if err := r.ParseForm(); err != nil {
			log.Warn(
				"failed parsing submitted form",
				zap.String("request_id", reqID),
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
					log.Warn(
						"request payload contains unsupported field",
						zap.String("request_id", reqID),
						zap.String("field_name", k),
					)
					message = "Failed processing the registration form due to unsupported field"
					validUserRegistration = false
					break
				}
			}
		}

		// Inspect registration values.
		if userSecret != userSecretConfirm {
			validUserRegistration = false
			message = "Failed processing the registration form due to mismatched passwords"
		}

		if registration.Code != "" {
			if userCode != registration.Code {
				validUserRegistration = false
				message = "Failed processing the registration form due to invalid verification code"
			}
		}

		if registration.RequireAcceptTerms {
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
				if registration.RequireDomainMailRecord {
					emailOpts["check_domain_mx"] = true
				}
				if err := validators.ValidateUserInput(k, userMail, emailOpts); err != nil {
					validUserRegistration = false
					message = "Failed processing the registration form due " + err.Error()
				}
			}
		}
		if !validUserRegistration {
			log.Warn(
				"failed registration",
				zap.String("request_id", reqID),
				zap.String("error", message),
			)
		}
	}

	// Display registration page
	resp := uiFactory.GetArgs()
	if registration.Title == "" {
		resp.Title = "Sign Up"
	} else {
		resp.Title = registration.Title
	}

	if registration.RequireAcceptTerms {
		resp.Data["require_accept_terms"] = true
	}

	if registration.Code != "" {
		resp.Data["require_registration_code"] = true
	}

	if message != "" {
		resp.Message = message
	}

	if r.Method == "POST" && validUserRegistration {
		// Perform registration tasks
		user := identity.NewUser(userHandle)
		if err := user.AddPassword(userSecret); err != nil {
			validUserRegistration = false
			message = "Internal Server Error"
			log.Warn("failed associating password during registration",
				zap.String("request_id", reqID),
				zap.String("error", err.Error()),
			)
		}
		if err := user.AddEmailAddress(userMail); err != nil {
			validUserRegistration = false
			message = "Internal Server Error"
			log.Warn("failed associating email address during registration",
				zap.String("request_id", reqID),
				zap.String("error", err.Error()),
			)
		}
		if err := user.AddRole("registration_pending"); err != nil {
			validUserRegistration = false
			message = "Internal Server Error"
			log.Warn("failed associating user role during registration",
				zap.String("request_id", reqID),
				zap.String("error", err.Error()),
			)
		}
		if err := registrationDatabase.AddUser(user); err != nil {
			validUserRegistration = false
			message = "Failed Registration"
			log.Warn("failed adding user to registration database",
				zap.String("request_id", reqID),
				zap.String("error", err.Error()),
			)
		}
		if err := registrationDatabase.SaveToFile(registration.Dropbox); err != nil {
			validUserRegistration = false
			message = "Internal Server Error"
			log.Warn("failed saving registration database",
				zap.String("request_id", reqID),
				zap.String("error", err.Error()),
			)
		}
		if validUserRegistration {
			log.Info("Processed registration",
				zap.String("request_id", reqID),
				zap.String("username", userHandle),
				zap.String("email", userMail),
			)
		}
	}

	if r.Method == "POST" {
		if !validUserRegistration {
			if message == "" {
				resp.Message = "Failed registration"
			} else {
				resp.Message = message
			}
		} else {
			resp.Title = "Thank you!"
			resp.Data["registered"] = true
		}
	}

	content, err := uiFactory.Render("register", resp)
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
