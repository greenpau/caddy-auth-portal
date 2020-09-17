package portal

import (
	//"encoding/json"
	//jwt "github.com/greenpau/caddy-auth-jwt"
	"go.uber.org/zap"
	"net/http"
	//"net/url"
)

// HandleRegister returns registration page.
func (m *AuthPortal) HandleRegister(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	var message string
	var maxBytesLimit int64 = 1000
	var minBytesLimit int64 = 15
	var userHandle, userMail, userSecret, userSecretConfirm, userCode string
	var userAccept, validUserRegistration bool
	reqID := opts["request_id"].(string)

	if opts["authenticated"].(bool) {
		w.Header().Set("Location", m.AuthURLPath)
		w.WriteHeader(302)
		return nil
	}

	if m.UserRegistration.Disabled {
		opts["flow"] = "unsupported_feature"
		return m.HandleGeneric(w, r, opts)
	}

	if m.UserRegistration.Dropbox == "" {
		opts["flow"] = "unsupported_feature"
		return m.HandleGeneric(w, r, opts)
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
		return m.HandleGeneric(w, r, opts)
	}

	// Handle registration submission
	if r.Method == "POST" {
		validUserRegistration = true
		if r.ContentLength > maxBytesLimit || r.ContentLength < minBytesLimit {
			m.logger.Warn(
				"request payload violated limits",
				zap.String("request_id", reqID),
				zap.Int64("min_size_limit", minBytesLimit),
				zap.Int64("max_size_limit", maxBytesLimit),
				zap.Int64("request_size", r.ContentLength),
			)
			opts["flow"] = "policy_violation"
			return m.HandleGeneric(w, r, opts)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			m.logger.Warn(
				"request payload violated content type",
				zap.String("request_id", reqID),
				zap.String("request_content_type", r.Header.Get("Content-Type")),
				zap.String("expected_content_type", "application/x-www-form-urlencoded"),
			)
			opts["flow"] = "policy_violation"
			return m.HandleGeneric(w, r, opts)
		}

		if err := r.ParseForm(); err != nil {
			m.logger.Warn(
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
					m.logger.Warn(
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

		if m.UserRegistration.Code != "" {
			if userCode != m.UserRegistration.Code {
				validUserRegistration = false
				message = "Failed processing the registration form due to invalid verification code"
			}
		}

		if m.UserRegistration.RequireAcceptTerms {
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
				if err := validateUserInput("handle", userHandle, handleOpts); err != nil {
					validUserRegistration = false
					message = "Failed processing the registration form due " + err.Error()
				}
			case "password":
				secretOpts := make(map[string]interface{})
				if err := validateUserInput("secret", userSecret, secretOpts); err != nil {
					validUserRegistration = false
					message = "Failed processing the registration form due " + err.Error()
				}
			case "email":
				emailOpts := make(map[string]interface{})
				if m.UserRegistration.RequireDomainMailRecord {
					emailOpts["check_domain_mx"] = true
				}
				if err := validateUserInput(k, userMail, emailOpts); err != nil {
					validUserRegistration = false
					message = "Failed processing the registration form due " + err.Error()
				}
			}
		}
		if !validUserRegistration {
			m.logger.Warn(
				"failed registration",
				zap.String("request_id", reqID),
				zap.String("error", message),
			)
		}
	}

	// Display registration page
	resp := m.uiFactory.GetArgs()
	resp.Data = make(map[string]interface{})
	if m.UserRegistration.Title == "" {
		resp.Title = "Sign Up"
	} else {
		resp.Title = m.UserRegistration.Title
	}

	if m.UserRegistration.RequireAcceptTerms {
		resp.Data["require_accept_terms"] = true
	}

	if m.UserRegistration.Code != "" {
		resp.Data["require_registration_code"] = true
	}

	if message != "" {
		resp.Message = message
	}

	if r.Method == "POST" {
		if !validUserRegistration {
			if message == "" {
				resp.Message = "Failed registration"
			}
		} else {
			resp.Title = "Thank you!"
			resp.Data["registered"] = true
		}
	}

	content, err := m.uiFactory.Render("register", resp)
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
