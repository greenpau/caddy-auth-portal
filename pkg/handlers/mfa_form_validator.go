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
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func validateMfaAuthTokenForm(r *http.Request, opts map[string]interface{}) (map[string]string, error) {
	resp := make(map[string]string)

	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return nil, fmt.Errorf("Unsupported content type")
	}
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("Failed parsing submitted form")
	}

	passcode := r.PostFormValue("passcode")
	passcode = strings.TrimSpace(passcode)
	if passcode == "" {
		return nil, fmt.Errorf("Required form passcode field is empty")
	}

	if len(passcode) < 4 || len(passcode) > 8 {
		return nil, fmt.Errorf("MFA passcode is not 4-8 characters long")
	}

	for _, c := range passcode {
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("MFA passcode contains non-numeric value")
		}
	}

	resp["passcode"] = passcode

	if opts != nil {
		if _, exists := opts["validate_token_id"]; exists {
			tokenID := r.PostFormValue("token_id")
			tokenID = strings.TrimSpace(tokenID)
			if tokenID == "" {
				return nil, fmt.Errorf("Required form token_id field is empty")
			}
			resp["token_id"] = tokenID
		}
		if v, exists := opts["validate_sandbox_id"]; exists {
			sandboxID := r.PostFormValue("sandbox_id")
			sandboxID = strings.TrimSpace(sandboxID)
			if sandboxID == "" {
				return nil, fmt.Errorf("Required form sandbox_id field is empty")
			}
			if sandboxID != v.(string) {
				return nil, fmt.Errorf("The value of the required form sandbox_id field does not match the expected value")
			}
		}
	}
	return resp, nil
}

func validateAddU2FTokenForm(r *http.Request) (map[string]string, error) {
	resp := make(map[string]string)
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return nil, fmt.Errorf("Unsupported content type")
	}
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("Failed parsing submitted form")
	}
	for _, k := range []string{"webauthn_register", "webauthn_challenge"} {
		if r.PostFormValue(k) == "" {
			return nil, fmt.Errorf("Required form %s field not found", k)
		}
		resp[k] = r.PostFormValue(k)
	}
	return resp, nil
}

func validateAddMfaTokenForm(r *http.Request) (map[string]string, error) {
	resp := make(map[string]string)
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return nil, fmt.Errorf("Unsupported content type")
	}
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("Failed parsing submitted form")
	}
	for _, k := range []string{"code1", "code2", "secret", "type"} {
		if r.PostFormValue(k) == "" {
			return nil, fmt.Errorf("Required form %s field not found", k)
		}
	}

	// Codes
	var code1, code2 string
	for _, i := range []string{"1", "2"} {
		code := r.PostFormValue("code" + i)
		if code == "" {
			return nil, fmt.Errorf("MFA code %s is empty", i)
		}
		if len(code) < 4 || len(code) > 8 {
			return nil, fmt.Errorf("MFA code %s is not 4-8 characters", i)
		}
		if i == "1" {
			code1 = code
			continue
		}
		code2 = code
		if code2 == code1 {
			return nil, fmt.Errorf("MFA code 1 and 2 match")
		}
		if len(code2) != len(code1) {
			return nil, fmt.Errorf("MFA code 1 and 2 have different length")
		}
	}
	resp["code1"] = code1
	resp["code2"] = code2

	// Comment
	comment := r.PostFormValue("comment")
	if comment != "" {
		resp["comment"] = comment
	}
	// Secret
	secret := r.PostFormValue("secret")
	if secret == "" {
		return nil, fmt.Errorf("MFA secret is empty")
	}
	resp["secret"] = secret

	// Type
	secretType := r.PostFormValue("type")
	switch secretType {
	case "":
		return nil, fmt.Errorf("MFA type is empty")
	case "totp":
	default:
		return nil, fmt.Errorf("MFA type is unsupported")
	}
	resp["type"] = secretType

	// Period
	period := r.PostFormValue("period")
	if period == "" {
		return nil, fmt.Errorf("MFA period is empty")
	}
	periodInt, err := strconv.Atoi(period)
	if err != nil {
		return nil, fmt.Errorf("MFA period is invalid")
	}
	if period != strconv.Itoa(periodInt) {
		return nil, fmt.Errorf("MFA period is invalid")
	}
	if periodInt < 30 || periodInt > 180 {
		return nil, fmt.Errorf("MFA period is invalid")
	}
	resp["period"] = period

	// Digits
	digits := r.PostFormValue("digits")
	if digits == "" {
		return nil, fmt.Errorf("MFA digits is empty")
	}
	digitsInt, err := strconv.Atoi(digits)
	if err != nil {
		return nil, fmt.Errorf("MFA digits is invalid")
	}
	if digits != strconv.Itoa(digitsInt) {
		return nil, fmt.Errorf("MFA digits is invalid")
	}
	if digitsInt < 4 || digitsInt > 8 {
		return nil, fmt.Errorf("MFA digits is invalid")
	}
	resp["digits"] = digits
	return resp, nil
}
