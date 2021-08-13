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
	// "encoding/json"
	"encoding/base64"
	"fmt"
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
	"github.com/greenpau/caddy-auth-portal/pkg/backends"
	"github.com/greenpau/caddy-auth-portal/pkg/enums/operator"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"github.com/greenpau/go-identity"
	"github.com/greenpau/go-identity/pkg/qr"
	"github.com/greenpau/go-identity/pkg/requests"
	"github.com/skip2/go-qrcode"
	// "go.uber.org/zap"
	"net/http"
	"strings"
)

func (p *Authenticator) handleHTTPMfaBarcode(ctx context.Context, w http.ResponseWriter, r *http.Request, endpoint string) error {
	qrCodeEncoded := strings.TrimPrefix(endpoint, "/mfa/barcode/")
	qrCodeEncoded = strings.TrimSuffix(qrCodeEncoded, ".png")
	codeURI, err := base64.StdEncoding.DecodeString(qrCodeEncoded)
	if err != nil {
		return p.handleHTTPRenderPlainText(ctx, w, http.StatusBadRequest)
	}
	png, err := qrcode.Encode(string(codeURI), qrcode.Medium, 256)
	if err != nil {
		return p.handleHTTPRenderPlainText(ctx, w, http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
	return nil
}

func (p *Authenticator) handleHTTPMfaSettings(
	ctx context.Context, r *http.Request, rr *requests.Request,
	usr *user.User, backend *backends.Backend, data map[string]interface{},
) error {
	var action string
	var status bool
	entrypoint := "mfa"
	data["view"] = entrypoint
	endpoint, err := getEndpoint(r.URL.Path, "/"+entrypoint)
	if err != nil {
		return err
	}

	switch {
	case strings.HasPrefix(endpoint, "/add/u2f") && r.Method == "POST":
		// Add U2F token.
		action = "add-u2f"
		status = true
		if err := validateAddU2FTokenForm(r, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("Bad Request: %s", err))
			break
		}
		if err = backend.Request(operator.AddMfaToken, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("%v", err))
			break
		}
		attachSuccessStatus(data, "U2F token has been added")
	case strings.HasPrefix(endpoint, "/add/u2f"):
		// Add U2F token.
		action = "add-u2f"
		data["webauthn_challenge"] = utils.GetRandomStringFromRange(64, 92)
		data["webauthn_rp_name"] = "AUTHP"
		data["webauthn_user_id"] = usr.Claims.ID
		data["webauthn_user_email"] = usr.Claims.Email
		data["webauthn_user_verification"] = "discouraged"
		data["webauthn_attestation"] = "direct"
		if usr.Claims.Name == "" {
			data["webauthn_user_display_name"] = usr.Claims.Subject
		} else {
			data["webauthn_user_display_name"] = usr.Claims.Name
		}
	case strings.HasPrefix(endpoint, "/add/app") && r.Method == "POST":
		// Add Application MFA token.
		action = "add-app"
		status = true
		if err := validateAddMfaTokenForm(r, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("Bad Request: %s", err))
			break
		}
		if err = backend.Request(operator.AddMfaToken, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("%v", err))
			break
		}
		attachSuccessStatus(data, "MFA token has been added")
	case strings.HasPrefix(endpoint, "/add/app"):
		action = "add-app"
		qr := qr.NewCode()
		qr.Secret = utils.GetRandomStringFromRange(64, 92)
		qr.Type = "totp"
		qr.Label = fmt.Sprintf("AUTHP:%s", usr.Claims.Email)
		qr.Period = 30
		qr.Issuer = "AUTHP"
		qr.Digits = 6
		if err := qr.Build(); err != nil {
			attachFailStatus(data, fmt.Sprintf("Failed creating QR code: %v", err))
			break
		}
		data["mfa_label"] = qr.Issuer
		data["mfa_comment"] = "My Authentication App"
		data["mfa_email"] = usr.Claims.Email
		data["mfa_type"] = qr.Type
		data["mfa_secret"] = qr.Secret
		data["mfa_period"] = fmt.Sprintf("%d", qr.Period)
		data["mfa_digits"] = fmt.Sprintf("%d", qr.Digits)
		data["code_uri"] = qr.Get()
		data["code_uri_encoded"] = qr.GetEncoded()
	case strings.HasPrefix(endpoint, "/test/app"):
		// Test Application MFA token.
		action = "test-app"
		if r.Method == "POST" {
			status = true
		}
		tokenID, digitCount, err := validateTestMfaTokenURL(endpoint)
		data["mfa_token_id"] = tokenID
		data["mfa_digits"] = digitCount
		if err != nil {
			attachFailStatus(data, fmt.Sprintf("Bad Request: %v", err))
			break
		}
		if r.Method != "POST" {
			break
		}
		// Validate the posted MFA token.
		if err := validateMfaAuthTokenForm(r, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("Bad Request: %v", err))
			break
		}
		if err = backend.Request(operator.GetMfaTokens, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("%v", err))
			break
		}
		var tokenValidated bool
		bundle := rr.Response.Payload.(*identity.MfaTokenBundle)
		for _, token := range bundle.Get() {
			if token.ID != rr.MfaToken.ID {
				continue
			}
			if err := token.ValidateCode(rr.MfaToken.Passcode); err != nil {
				continue
			}
			tokenValidated = true
			attachSuccessStatus(data, fmt.Sprintf("token id %s tested successfully", token.ID))
			break
		}
		if tokenValidated {
			break
		}
		attachFailStatus(data, "Invalid token passcode")
	case strings.HasPrefix(endpoint, "/test/u2f"):
		// Test U2F token.
		var token *identity.MfaToken
		action = "test-u2f"
		tokenID, err := validateTestU2FTokenURL(endpoint)
		data["mfa_token_id"] = tokenID
		if err != nil {
			status = true
			attachFailStatus(data, fmt.Sprintf("Bad Request: %v", err))
			break
		}
		// Get a list of U2F tokens.
		if err = backend.Request(operator.GetMfaTokens, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("%v", err))
			break
		}
		bundle := rr.Response.Payload.(*identity.MfaTokenBundle)
		for _, t := range bundle.Get() {
			if t.ID != tokenID {
				continue
			}
			if t.Type != "u2f" {
				continue
			}
			token = t
			break
		}
		if token == nil {
			status = true
			attachFailStatus(data, fmt.Sprintf("Bad Request: U2F token id %s not found", tokenID))
			break
		}
		if r.Method != "POST" {
			// Authentication Ceremony parameters.
			// Reference: https://www.w3.org/TR/webauthn-2/#sctn-assertion-privacy
			if token.Parameters == nil {
				status = true
				attachFailStatus(data, fmt.Sprintf("Bad Request: U2F token id %s has no U2F parameters", tokenID))
				break
			}
			validParams := true
			for _, k := range []string{"id", "transports", "type"} {
				if _, exists := token.Parameters["u2f_"+k]; !exists {
					status = true
					validParams = false
					attachFailStatus(data, fmt.Sprintf("U2F token id %s has no %s U2F parameters", tokenID, k))
					break
				}
			}
			if !validParams {
				break
			}
			var tokenTransports string
			if len(token.Parameters["u2f_transports"]) > 0 {
				tokenTransports = fmt.Sprintf(`"%s"`, strings.Join(strings.Split(token.Parameters["u2f_transports"], ","), `","`))
			}
			data["webauthn_challenge"] = utils.GetRandomStringFromRange(64, 92)
			data["webauthn_rp_name"] = "AUTHP"
			data["webauthn_timeout"] = "60000"
			// See https://chromium.googlesource.com/chromium/src/+/refs/heads/main/content/browser/webauth/uv_preferred.md
			// data["webauthn_user_verification"] = "preferred"
			data["webauthn_user_verification"] = "discouraged"
			// data["webauthn_ext_uvm"] = "true"
			data["webauthn_ext_uvm"] = "false"
			data["webauthn_ext_loc"] = "false"
			data["webauthn_tx_auth_simple"] = "Could you please verify yourself?"
			var allowedCredentials []map[string]interface{}
			allowedCredential := make(map[string]interface{})
			allowedCredential["id"] = token.Parameters["u2f_id"]
			allowedCredential["type"] = token.Parameters["u2f_type"]
			allowedCredential["transports"] = tokenTransports
			allowedCredentials = append(allowedCredentials, allowedCredential)
			data["webauthn_credentials"] = allowedCredentials
			break
		}
		// Validate the posted U2F token.
		status = true
		if err := validateAuthU2FTokenForm(r, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("Bad Request: %v", err))
			break
		}
		if err := token.WebAuthnRequest(rr.WebAuthn.Request); err != nil {
			attachFailStatus(data, fmt.Sprintf("U2F authentication failed: %v", err))
			break
		}
		attachSuccessStatus(data, fmt.Sprintf("U2F token id %s tested successfully", token.ID))
	case strings.HasPrefix(endpoint, "/delete"):
		// Delete a particular SSH key.
		action = "delete"
		status = true
		tokenID, err := getEndpointKeyID(endpoint, "/delete/")
		if err != nil {
			attachFailStatus(data, fmt.Sprintf("%v", err))
			break
		}
		rr.MfaToken.ID = tokenID
		if err = backend.Request(operator.DeleteMfaToken, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("failed deleting token id %s: %v", tokenID, err))
			break
		}
		attachSuccessStatus(data, fmt.Sprintf("token id %s deleted successfully", tokenID))
		/*
			case strings.HasPrefix(endpoint, "/view"):
				// Get a particular SSH key.
				action = "view"
				keyID, err := getEndpointKeyID(endpoint, "/view/")
				if err != nil {
					attachFailStatus(data, fmt.Sprintf("%v", err))
					break
				}
				rr.Key.Usage = "ssh"
				if err = backend.Request(operator.GetPublicKeys, rr); err != nil {
					attachFailStatus(data, fmt.Sprintf("failed fetching key id %s: %v", keyID, err))
					break
				}
				bundle := rr.Response.Payload.(*identity.PublicKeyBundle)
				for _, k := range bundle.Get() {
					if k.ID != keyID {
						continue
					}
					var keyMap map[string]interface{}
					keyBytes, _ := json.Marshal(k)
					json.Unmarshal(keyBytes, &keyMap)
					for _, w := range []string{"payload", "openssh"} {
						if _, exists := keyMap[w]; !exists {
							continue
						}
						delete(keyMap, w)
					}
					prettyKey, _ := json.MarshalIndent(keyMap, "", "  ")
					attachSuccessStatus(data, "OK")
					data["key"] = string(prettyKey)
					if k.Payload != "" {
						data["pem_key"] = k.Payload
					}
					if k.OpenSSH != "" {
						data["openssh_key"] = k.OpenSSH
					}
					break
				}
		*/
	default:
		// List MFA Tokens.
		if err = backend.Request(operator.GetMfaTokens, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("%v", err))
			break
		}
		bundle := rr.Response.Payload.(*identity.MfaTokenBundle)
		tokens := bundle.Get()
		if len(tokens) > 0 {
			data["mfa_tokens"] = tokens
		}
		attachSuccessStatus(data, "OK")
	}
	attachView(data, entrypoint, action, status)
	return nil
}
