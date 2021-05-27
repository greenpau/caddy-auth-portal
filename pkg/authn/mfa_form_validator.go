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
	"fmt"
	"github.com/greenpau/go-identity/pkg/requests"
	"net/http"
	"strconv"
	"strings"
)

func validateAuthU2FTokenForm(r *http.Request, rr *requests.Request) error {
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return fmt.Errorf("Unsupported content type")
	}
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("Failed parsing submitted form")
	}
	rr.WebAuthn.Request = strings.TrimSpace(r.PostFormValue("webauthn_request"))
	if rr.WebAuthn.Request == "" {
		return fmt.Errorf("Required form %s field not found", "webauthn_request")
	}
	rr.MfaToken.Type = "u2f"
	tokenID := r.PostFormValue("token_id")
	tokenID = strings.TrimSpace(tokenID)
	if tokenID != "" {
		rr.MfaToken.ID = tokenID
	}
	return nil
}

func validateMfaAuthTokenForm(r *http.Request, rr *requests.Request) error {
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return fmt.Errorf("Unsupported content type")
	}
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("Failed parsing submitted form")
	}
	passcode := r.PostFormValue("passcode")
	passcode = strings.TrimSpace(passcode)
	if passcode == "" {
		return fmt.Errorf("Required form passcode field is empty")
	}

	if len(passcode) < 4 || len(passcode) > 8 {
		return fmt.Errorf("MFA passcode is not 4-8 characters long")
	}
	for _, c := range passcode {
		if c < '0' || c > '9' {
			return fmt.Errorf("MFA passcode contains non-numeric value")
		}
	}
	rr.MfaToken.Passcode = passcode
	tokenID := r.PostFormValue("token_id")
	tokenID = strings.TrimSpace(tokenID)
	if tokenID != "" {
		rr.MfaToken.ID = tokenID
	}
	return nil
}

func validateAddU2FTokenForm(r *http.Request, rr *requests.Request) error {
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return fmt.Errorf("Unsupported content type")
	}
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("Failed parsing submitted form")
	}
	for _, k := range []string{"webauthn_register", "webauthn_challenge", "comment"} {
		v := strings.TrimSpace(r.PostFormValue(k))
		if v == "" {
			return fmt.Errorf("Required form %s field not found", k)
		}
		switch k {
		case "webauthn_register":
			rr.WebAuthn.Register = v
		case "webauthn_challenge":
			rr.WebAuthn.Challenge = v
		case "comment":
			rr.MfaToken.Comment = v
		}
	}
	rr.MfaToken.Type = "u2f"
	return nil
}

func validateAddMfaTokenForm(r *http.Request, rr *requests.Request) error {
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return fmt.Errorf("Unsupported content type")
	}
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("Failed parsing submitted form")
	}
	for _, k := range []string{"passcode", "secret", "type"} {
		if r.PostFormValue(k) == "" {
			return fmt.Errorf("Required form %s field not found", k)
		}
	}

	// Passcode
	code := r.PostFormValue("passcode")
	if code == "" {
		return fmt.Errorf("MFA passcode is empty")
	}
	if len(code) < 4 || len(code) > 8 {
		return fmt.Errorf("MFA passcode is not 4-8 characters")
	}
	rr.MfaToken.Passcode = code

	// Comment
	comment := r.PostFormValue("comment")
	if comment != "" {
		rr.MfaToken.Comment = comment
	}
	// Secret
	secret := r.PostFormValue("secret")
	if secret == "" {
		return fmt.Errorf("MFA secret is empty")
	}
	rr.MfaToken.Secret = secret

	// Type
	secretType := r.PostFormValue("type")
	switch secretType {
	case "":
		return fmt.Errorf("MFA type is empty")
	case "totp":
	default:
		return fmt.Errorf("MFA type is unsupported")
	}
	rr.MfaToken.Type = secretType

	// Period
	period := r.PostFormValue("period")
	if period == "" {
		return fmt.Errorf("MFA period is empty")
	}
	periodInt, err := strconv.Atoi(period)
	if err != nil {
		return fmt.Errorf("MFA period is invalid")
	}
	if period != strconv.Itoa(periodInt) {
		return fmt.Errorf("MFA period is invalid")
	}
	if periodInt < 30 || periodInt > 180 {
		return fmt.Errorf("MFA period is invalid")
	}
	rr.MfaToken.Period = periodInt

	// Digits
	digits := r.PostFormValue("digits")
	if digits == "" {
		return fmt.Errorf("MFA digits is empty")
	}
	digitsInt, err := strconv.Atoi(digits)
	if err != nil {
		return fmt.Errorf("MFA digits is invalid")
	}
	if digits != strconv.Itoa(digitsInt) {
		return fmt.Errorf("MFA digits is invalid")
	}
	if digitsInt < 4 || digitsInt > 8 {
		return fmt.Errorf("MFA digits is invalid")
	}
	rr.MfaToken.Digits = digitsInt
	return nil
}

func validateTestMfaTokenURL(endpoint string) (string, string, error) {
	arr, err := parseEndpointPath(endpoint, "/test/app/", 2)
	if err != nil {
		return "", "", fmt.Errorf("malformed URL: %v", err)
	}
	tokenID, err := parseID(arr[1])
	if err != nil {
		return "", "", fmt.Errorf("malformed URL: %v", err)
	}
	switch arr[0] {
	case "4", "6", "8":
	default:
		return "", "", fmt.Errorf("malformed URL")
	}
	return tokenID, arr[0], nil
}

func validateTestU2FTokenURL(endpoint string) (string, error) {
	arr, err := parseEndpointPath(endpoint, "/test/u2f/", 2)
	if err != nil {
		return "", fmt.Errorf("malformed URL: %v", err)
	}
	switch arr[0] {
	case "generic":
	default:
		return "", fmt.Errorf("unsupported URL identifier")
	}
	tokenID, err := parseID(arr[1])
	if err != nil {
		return "", fmt.Errorf("malformed URL: %v", err)
	}
	return tokenID, nil
}

func parseEndpointPath(p, prefix string, length int) ([]string, error) {
	p = strings.TrimPrefix(p, prefix)
	arr := strings.Split(p, "/")
	if len(arr) != length {
		return arr, fmt.Errorf("unexpected endpoint path")
	}
	return arr, nil
}

func parseID(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return "", fmt.Errorf("id is empty")
	}
	if len(s) > 96 {
		return "", fmt.Errorf("id is too long")
	}
	return s, nil
}
