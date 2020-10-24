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

package validators

import (
	"fmt"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"net"
	"regexp"
	"strings"
)

const usernameCharset = "0123456789abcdefghijklmnopqrstuvwxyz"

var emailAddrRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

// ValidateUserInput provides generic interface to validate user input.
func ValidateUserInput(k, v string, opts map[string]interface{}) error {
	if v == "" {
		return fmt.Errorf("empty %s value", k)
	}
	switch k {
	case "handle":
		if err := ValidateUserInputHandle(v, opts); err != nil {
			return err
		}
	case "secret":
		if err := ValidateUserInputSecret(v, opts); err != nil {
			return err
		}
	case "email":
		if err := ValidateUserInputEmail(v, opts); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s validation is unsupported", k)
	}
	return nil
}

// ValidateUserInputHandle validates provided user handle.
func ValidateUserInputHandle(v string, opts map[string]interface{}) error {
	if len(v) > 25 {
		return fmt.Errorf("the handle character length should not exceed 25 characters")
	}
	if err := utils.ContainsInvalidChars(usernameCharset, v); err != nil {
		return fmt.Errorf("the handle %s", err.Error())
	}
	return nil
}

// ValidateUserInputSecret validates provided user secret.
func ValidateUserInputSecret(v string, opts map[string]interface{}) error {
	if len(v) > 255 {
		return fmt.Errorf("the handle character length should not exceed 255 characters")
	}
	return nil
}

// ValidateUserInputEmail validates provided email address.
func ValidateUserInputEmail(v string, opts map[string]interface{}) error {
	if len(v) < 3 && len(v) > 254 {
		return fmt.Errorf("the length of email address is invalid")
	}
	if !emailAddrRegex.MatchString(v) {
		return fmt.Errorf("the email address is invalid")
	}
	emailParts := strings.SplitN(v, "@", 2)
	if len(emailParts) != 2 {
		return fmt.Errorf("the email address is invalid")
	}
	if opts != nil {
		if enabled, exists := opts["check_domain_mx"]; exists {
			if enabled.(bool) {
				rr, err := net.LookupMX(emailParts[1])
				if err != nil {
					return fmt.Errorf("the email address domain is invalid")
				}
				if len(rr) < 1 {
					return fmt.Errorf("the email address domain is misconfigured")
				}
			}
		}
	}
	return nil
}
