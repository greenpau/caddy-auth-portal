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

package utils

import (
	"encoding/base32"
	"fmt"
	"net/url"
	"strings"
)

// GetCodeURI returns TOTP/HOTP Key URI
func GetCodeURI(opts map[string]interface{}) (string, error) {
	if opts == nil {
		return "", fmt.Errorf("parameters are missing")
	}
	var codeType, label, secret, issuer, algo string
	var period, digits, counter int
	var sb strings.Builder
	for _, k := range []string{"type", "label", "secret"} {
		if _, exists := opts[k]; !exists {
			return "", fmt.Errorf("%s is required but missing", k)
		}
	}

	for _, k := range []string{"type", "label", "secret", "issuer", "algorithm"} {
		if v, exists := opts[k]; exists {
			switch vt := v.(type) {
			case string:
				switch k {
				case "type":
					codeType = v.(string)
				case "label":
					label = v.(string)
				case "secret":
					secret = v.(string)
				case "issuer":
					issuer = v.(string)
				case "algorithm":
					algo = v.(string)
				}
			default:
				return "", fmt.Errorf("%s is not a string, but %s", k, vt)
			}
		}
	}

	for _, k := range []string{"digits", "period", "counter"} {
		if v, exists := opts[k]; exists {
			switch vt := v.(type) {
			case int:
				switch k {
				case "digits":
					digits = v.(int)
					if digits < 4 || digits > 8 {
						return "", fmt.Errorf("%s must be between 4 and 8 digits long", k)
					}
				case "period":
					period = v.(int)
				case "counter":
					counter = v.(int)
				}
			default:
				return "", fmt.Errorf("%s is not an integer, but %s", k, vt)
			}
		}
	}

	sb.WriteString("otpauth://")
	if codeType != "hotp" && codeType != "totp" {
		return "", fmt.Errorf("key type %s is invalid", codeType)
	}
	if label == "" {
		return "", fmt.Errorf("key label is empty")
	}
	if secret == "" {
		return "", fmt.Errorf("key secret is empty")
	}
	if algo != "" {
		if algo != "SHA1" && algo != "SHA256" && algo != "SHA512" {
			return "", fmt.Errorf("key algorithm %s is invalid", algo)
		}
	}
	if codeType == "hotp" && counter < 1 {
		return "", fmt.Errorf("key type %s requires counter value", codeType)
	}

	sb.WriteString(codeType + "/" + url.QueryEscape(label))

	secretEncoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	sb.WriteString("?secret=" + secretEncoder.EncodeToString([]byte(secret)))

	if issuer != "" {
		sb.WriteString("&issuer=" + url.QueryEscape(issuer))
	}
	if algo != "" {
		sb.WriteString("&algorithm=" + algo)
	}
	if digits != 0 {
		sb.WriteString(fmt.Sprintf("&digits=%d", digits))
	}
	if counter > 0 {
		sb.WriteString(fmt.Sprintf("&counter=%d", counter))
	}
	if period > 0 {
		sb.WriteString(fmt.Sprintf("&period=%d", period))
	}
	return sb.String(), nil
}
