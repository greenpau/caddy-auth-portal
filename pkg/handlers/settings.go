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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	jwtclaims "github.com/greenpau/caddy-auth-jwt/pkg/claims"
	"github.com/greenpau/caddy-auth-portal/pkg/backends"
	"github.com/greenpau/caddy-auth-portal/pkg/ui"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"go.uber.org/zap"
)

// ServeSettings returns authenticated user information.
func ServeSettings(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	var codeURI string
	var codeErr error
	var backend *backends.Backend
	authURLPath := opts["auth_url_path"].(string)
	if !opts["authenticated"].(bool) {
		w.Header().Set("Location", authURLPath+"?redirect_url="+r.RequestURI)
		w.WriteHeader(302)
		return nil
	}
	reqID := opts["request_id"].(string)
	log := opts["logger"].(*zap.Logger)
	claims := opts["user_claims"].(*jwtclaims.UserClaims)
	uiFactory := opts["ui"].(*ui.UserInterfaceFactory)
	if _, exists := opts["backend"]; exists {
		backend = opts["backend"].(*backends.Backend)
	}
	view := strings.TrimPrefix(r.URL.Path, authURLPath)
	view = strings.TrimPrefix(view, "/")
	view = strings.TrimPrefix(view, "settings")
	view = strings.TrimPrefix(view, "/")
	viewParts := strings.Split(view, "/")
	view = viewParts[0]
	if view == "" {
		view = "general"
	}

	// Display main authentication portal page
	resp := uiFactory.GetArgs()
	resp.Title = "Settings"

	switch view {
	case "mfa":
		if len(viewParts) < 2 {
			// Entry Page
			args := make(map[string]interface{})
			args["username"] = claims.Subject
			args["email"] = claims.Email
			mfaTokens, err := backend.GetMfaTokens(args)
			if err != nil {
				resp.Data["status"] = "FAIL"
				resp.Data["status_reason"] = fmt.Sprintf("%s", err)
				break
			}
			if len(mfaTokens) > 0 {
				resp.Data["mfa_tokens"] = mfaTokens
			}
			break
		}

		switch viewParts[1] {
		case "barcode":
			if len(viewParts) < 3 {
				log.Error("Failed rendering key code URI barcode", zap.String("request_id", reqID), zap.String("error", "malformed barcode url"))
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(400)
				w.Write([]byte(`Bad Request`))
				return fmt.Errorf("malformed barcode url")
			}
			opts["code_uri_encoded"] = strings.TrimSuffix(strings.Join(viewParts[2:], "/"), ".png")
			return ServeBarcodeImage(w, r, opts)
		case "add":
			if len(viewParts) < 3 {
				break
			}
			switch viewParts[2] {
			case "app":
				// Application Authenticator
				if r.Method == "POST" {
					// view: mfa-add-app-status
					view = strings.Join(viewParts, "-") + "-status"
					resp.Data["status"] = "FAIL"
					if backend == nil {
						resp.Data["status_reason"] = "Authentication backend not found"
						break
					}
					// A user submitted add app authenticator form
					secrets, err := validateAddMfaTokenForm(r)
					if err != nil {
						resp.Data["status_reason"] = fmt.Sprintf("Bad Request: %s", err)
						break
					}
					operation := make(map[string]interface{})
					operation["name"] = "add_mfa_token"
					operation["type"] = "app"
					operation["username"] = claims.Subject
					operation["email"] = claims.Email
					for k, v := range secrets {
						operation[k] = v
					}
					if err := backend.Do(operation); err != nil {
						resp.Data["status_reason"] = fmt.Sprintf("%s", err)
						break
					}
					resp.Data["status"] = "SUCCESS"
					resp.Data["status_reason"] = "MFA token has been added"
					break
				}
				// A user arrived at add app authenticator form
				secretText := utils.GetRandomStringFromRange(64, 92)

				codeOpts := make(map[string]interface{})
				codeOpts["secret"] = secretText
				codeOpts["type"] = "totp"
				codeOpts["label"] = "AUTHP:" + claims.Email
				codeOpts["period"] = 30
				codeOpts["issuer"] = "AUTHP"
				codeOpts["digits"] = 6

				resp.Data["mfa_label"] = "AUTHP"
				resp.Data["mfa_comment"] = "My Authentication App"
				resp.Data["mfa_email"] = claims.Email
				resp.Data["mfa_type"] = "totp"
				resp.Data["mfa_secret"] = secretText
				resp.Data["mfa_period"] = "30"
				resp.Data["mfa_digits"] = "6"

				codeURI, codeErr = utils.GetCodeURI(codeOpts)
				if codeErr != nil {
					log.Error("Failed creating key code URI", zap.String("request_id", reqID), zap.String("error", codeErr.Error()))
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(500)
					w.Write([]byte(`Internal Server Error`))
					return codeErr
				}
				resp.Data["code_uri"] = codeURI
				resp.Data["code_uri_encoded"] = base64.StdEncoding.EncodeToString([]byte(codeURI))
				view = strings.Join(viewParts, "-")
			case "u2f":
				// U2F Token Authentication
				if r.Method == "POST" {
					// A user submits U2F token parameters.
					view = strings.Join(viewParts, "-") + "-status"
					resp.Data["status"] = "FAIL"
					if backend == nil {
						resp.Data["status_reason"] = "Authentication backend not found"
						break
					}
					secrets, err := validateAddU2FTokenForm(r)
					if err != nil {
						resp.Data["status_reason"] = fmt.Sprintf("Bad Request: %s", err)
						break
					}
					operation := make(map[string]interface{})
					operation["name"] = "add_mfa_token"
					operation["type"] = "u2f"
					operation["username"] = claims.Subject
					operation["email"] = claims.Email
					for k, v := range secrets {
						operation[k] = v
					}
					if err := backend.Do(operation); err != nil {
						resp.Data["status_reason"] = fmt.Sprintf("%s", err)
						break
					}
					resp.Data["status"] = "SUCCESS"
					resp.Data["status_reason"] = "MFA token has been added"
					break
				}
				// A user lands on add U2F token page.
				resp.Data["webauthn_challenge"] = utils.GetRandomStringFromRange(64, 92)
				resp.Data["webauthn_rp_name"] = "AUTHP"
				resp.Data["webauthn_user_id"] = claims.ID
				resp.Data["webauthn_user_email"] = claims.Email
				resp.Data["webauthn_user_verification"] = "discouraged"
				resp.Data["webauthn_attestation"] = "direct"
				if claims.Name == "" {
					resp.Data["webauthn_user_display_name"] = claims.Subject
				} else {
					resp.Data["webauthn_user_display_name"] = claims.Name
				}
				view = strings.Join(viewParts, "-")
			}
		case "delete":
			view = viewParts[0] + "-" + viewParts[1] + "-status"
			resp.Data["status"] = "FAIL"
			tokenID := viewParts[2]
			if len(viewParts) != 3 {
				resp.Data["status_reason"] = "malformed request"
				break
			}
			if tokenID == "" {
				resp.Data["status_reason"] = "token id not found"
				break
			}
			operation := make(map[string]interface{})
			operation["name"] = "delete_mfa_token"
			operation["token_id"] = tokenID
			operation["username"] = claims.Subject
			operation["email"] = claims.Email
			err := backend.Do(operation)
			if err != nil {
				resp.Data["status_reason"] = fmt.Sprintf("failed deleting token id %s: %s", tokenID, err)
				break
			}
			resp.Data["status"] = "SUCCESS"
			resp.Data["status_reason"] = fmt.Sprintf("token id %s deleted successfully", tokenID)
		case "test":
			if len(viewParts) < 4 {
				break
			}
			switch viewParts[2] {
			case "app":
				// A user arrived at test app authenticator form
				tokenID, digits, err := validateTestMfaTokenURL(viewParts)
				if err != nil {
					view = "mfa-test-app-status"
					resp.Data["status"] = "FAIL"
					resp.Data["status_reason"] = err.Error()
					resp.Data["mfa_token_id"] = tokenID
					resp.Data["mfa_digits"] = digits
					break
				}
				view = "mfa-test-app"
				resp.Data["mfa_token_id"] = tokenID
				resp.Data["mfa_digits"] = digits
				if r.Method != "POST" {
					break
				}

				// A user submitted passcode for verification
				view = "mfa-test-app-status"
				resp.Data["status"] = "FAIL"
				if backend == nil {
					resp.Data["status_reason"] = "Authentication backend not found"
					break
				}
				var passcodeValid bool
				validateOpts := map[string]interface{}{
					"validate_token_id": true,
				}
				formData, err := validateMfaAuthTokenForm(r, validateOpts)
				if err != nil {
					resp.Data["status_reason"] = fmt.Sprintf("Bad Request: %s", err)
					break
				}
				args := make(map[string]interface{})
				args["username"] = claims.Subject
				args["email"] = claims.Email
				mfaTokens, err := backend.GetMfaTokens(args)
				if err != nil {
					resp.Data["status_reason"] = fmt.Sprintf("%s", err)
					break
				}
				for _, mfaToken := range mfaTokens {
					if mfaToken.ID != formData["token_id"] {
						continue
					}
					if err := mfaToken.ValidateCode(formData["passcode"]); err == nil {
						passcodeValid = true
						resp.Data["status"] = "SUCCESS"
						resp.Data["status_reason"] = fmt.Sprintf("token %s validated successfully", mfaToken.ID)
						break
					}
				}
				if !passcodeValid {
					resp.Data["status_reason"] = fmt.Sprintf("invalid passcode")
				}
			case "u2f":
				// A user arrived at test u2f token form
				tokenID, err := validateTestMfaUniTokenURL(viewParts)
				if err != nil {
					view = "mfa-test-u2f-status"
					resp.Data["status"] = "FAIL"
					resp.Data["status_reason"] = err.Error()
					resp.Data["mfa_token_id"] = tokenID
					break
				}
				view = "mfa-test-u2f"
				resp.Data["mfa_token_id"] = tokenID
				if r.Method != "POST" {
					// A user lands on test U2F token page.
					resp.Data["webauthn_challenge"] = utils.GetRandomStringFromRange(64, 92)
					resp.Data["webauthn_rp_name"] = "AUTHP"
					resp.Data["webauthn_timeout"] = "60000"
					resp.Data["webauthn_user_verification"] = "preferred"
					resp.Data["webauthn_ext_uvm"] = "true"
					resp.Data["webauthn_ext_loc"] = "false"
					resp.Data["webauthn_tx_auth_simple"] = "Could you please verify yourself?"
					break
				}

				// A user submitted passcode for verification
				view = "mfa-test-u2f-status"
				resp.Data["status"] = "FAIL"
				if backend == nil {
					resp.Data["status_reason"] = "Authentication backend not found"
					break
				}
				var passcodeValid bool
				/*
					validateOpts := map[string]interface{}{
						"validate_token_id": true,
					}
					formData, err := validateMfaAuthTokenForm(r, validateOpts)
					if err != nil {
						resp.Data["status_reason"] = fmt.Sprintf("Bad Request: %s", err)
						break
					}
					args := make(map[string]interface{})
					args["username"] = claims.Subject
					args["email"] = claims.Email
					mfaTokens, err := backend.GetMfaTokens(args)
					if err != nil {
						resp.Data["status_reason"] = fmt.Sprintf("%s", err)
						break
					}
					for _, mfaToken := range mfaTokens {
						if mfaToken.ID != formData["token_id"] {
							continue
						}
						if err := mfaToken.ValidateCode(formData["passcode"]); err == nil {
							passcodeValid = true
							resp.Data["status"] = "SUCCESS"
							resp.Data["status_reason"] = fmt.Sprintf("token %s validated successfully", mfaToken.ID)
							break
						}
					}
				*/
				if !passcodeValid {
					resp.Data["status_reason"] = fmt.Sprintf("verification failed")
				}
			}
		}
	case "password":
		if len(viewParts) < 2 {
			break
		}
		view = strings.Join(viewParts, "-")
		switch viewParts[1] {
		case "edit":
			if r.Method == "POST" {
				resp.Data["status"] = "FAIL"
				if backend == nil {
					resp.Data["status_reason"] = "Authentication backend not found"
					break
				}
				secrets, err := validatePasswordChangeForm(r)
				if err != nil {
					resp.Data["status_reason"] = "Bad Request"
					break
				}
				operation := make(map[string]interface{})
				operation["name"] = "password_change"
				operation["username"] = claims.Subject
				operation["email"] = claims.Email
				for k, v := range secrets {
					operation[k] = v
				}
				if err := backend.Do(operation); err != nil {
					resp.Data["status_reason"] = fmt.Sprintf("%s", err)
					break
				}
				resp.Data["status"] = "SUCCESS"
				resp.Data["status_reason"] = "Password has been changed"
				break
			}
			view = viewParts[0]
		}
	case "sshkeys", "gpgkeys":
		view = strings.Join(viewParts, "-")
		if len(viewParts) < 2 {
			// Entry Page
			args := make(map[string]interface{})
			args["username"] = claims.Subject
			args["email"] = claims.Email
			switch view {
			case "sshkeys":
				args["key_usage"] = "ssh"
			case "gpgkeys":
				args["key_usage"] = "gpg"
			}
			pubKeys, err := backend.GetPublicKeys(args)
			if err != nil {
				resp.Data["status"] = "FAIL"
				resp.Data["status_reason"] = fmt.Sprintf("%s", err)
				break
			}
			if len(pubKeys) > 0 {
				resp.Data[view] = pubKeys
			}
			break
		}

		switch viewParts[1] {
		case "add":
			view = strings.Join(viewParts, "-")
			if r.Method == "POST" {
				view = strings.Join(viewParts, "-") + "-status"
				resp.Data["status"] = "FAIL"
				if backend == nil {
					resp.Data["status_reason"] = "Authentication backend not found"
					break
				}
				keys, err := validateKeyInputForm(r)
				if err != nil {
					resp.Data["status_reason"] = "Bad Request"
					break
				}
				operation := make(map[string]interface{})
				switch viewParts[0] {
				case "sshkeys":
					operation["name"] = "add_ssh_key"
				case "gpgkeys":
					operation["name"] = "add_gpg_key"
				}
				operation["username"] = claims.Subject
				operation["email"] = claims.Email
				for k, v := range keys {
					operation[k] = v
				}
				if err := backend.Do(operation); err != nil {
					resp.Data["status_reason"] = fmt.Sprintf("%s", err)
					break
				}
				resp.Data["status"] = "SUCCESS"
				switch viewParts[0] {
				case "sshkeys":
					resp.Data["status_reason"] = "Public SSH key has been added"
				case "gpgkeys":
					resp.Data["status_reason"] = "GPG key has been added"
				}
				break
			}
		case "view":
			view = viewParts[0] + "-" + viewParts[1]
			resp.Data["status"] = "FAIL"
			if len(viewParts) != 3 {
				resp.Data["status_reason"] = "malformed request"
				break
			}
			keyID := viewParts[2]
			if keyID == "" {
				resp.Data["status_reason"] = "key id not found"
				break
			}
			args := make(map[string]interface{})
			args["username"] = claims.Subject
			args["email"] = claims.Email
			switch viewParts[0] {
			case "sshkeys":
				args["key_usage"] = "ssh"
			case "gpgkeys":
				args["key_usage"] = "gpg"
			}
			pubKeys, err := backend.GetPublicKeys(args)
			if err != nil {
				resp.Data["status_reason"] = fmt.Sprintf("%s", err)
				break
			}
			for _, k := range pubKeys {
				if k.ID != keyID {
					continue
				}
				prettyKey, err := json.MarshalIndent(k, "", "  ")
				if err != nil {
					resp.Data["status_reason"] = fmt.Sprintf("%s", err)
					break
				}
				resp.Data["status"] = "SUCCESS"
				resp.Data["key"] = string(prettyKey)
				break
			}
			break
		case "delete":
			view = viewParts[0] + "-" + viewParts[1] + "-status"
			resp.Data["status"] = "FAIL"
			if len(viewParts) != 3 {
				resp.Data["status_reason"] = "malformed request"
				break
			}
			keyID := viewParts[2]
			if keyID == "" {
				resp.Data["status_reason"] = "key id not found"
				break
			}
			operation := make(map[string]interface{})
			operation["name"] = "delete_public_key"
			operation["key_id"] = keyID
			operation["username"] = claims.Subject
			operation["email"] = claims.Email
			if err := backend.Do(operation); err != nil {
				resp.Data["status_reason"] = fmt.Sprintf("failed deleting key id %s: %s", keyID, err)
				break
			}
			resp.Data["status"] = "SUCCESS"
			resp.Data["status_reason"] = fmt.Sprintf("key id %s deleted successfully", keyID)
		}
	case "apikeys":
		if len(viewParts) < 2 {
			break
		}
		view = strings.Join(viewParts, "-")
		switch viewParts[1] {
		case "add":
			if r.Method == "POST" {
				view = strings.Join(viewParts, "-") + "-status"
				resp.Data["status"] = "FAIL"
				if backend == nil {
					resp.Data["status_reason"] = "Authentication backend not found"
					break
				}
				keys, err := validateKeyInputForm(r)
				if err != nil {
					resp.Data["status_reason"] = "Bad Request"
					break
				}
				operation := make(map[string]interface{})
				operation["name"] = "add_api_key"
				operation["username"] = claims.Subject
				operation["email"] = claims.Email
				for k, v := range keys {
					operation[k] = v
				}
				if err := backend.Do(operation); err != nil {
					resp.Data["status_reason"] = fmt.Sprintf("%s", err)
					break
				}
				resp.Data["status"] = "SUCCESS"
				resp.Data["status_reason"] = "API key has been added"
				break
			}
		}
	}

	resp.Data["view"] = view

	content, err := uiFactory.Render("settings", resp)
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
