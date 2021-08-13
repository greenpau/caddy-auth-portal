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

package saml

import (
	"encoding/base64"
	"fmt"
	"github.com/greenpau/go-identity/pkg/requests"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Authenticate performs authentication.
func (b *Backend) Authenticate(r *requests.Request) error {
	r.Response.Code = 400
	if r.Upstream.Request.Method != "POST" {
		r.Response.Code = 200
		r.Response.RedirectURL = b.loginURL
		return nil
	}

	if 500 > r.Upstream.Request.ContentLength || r.Upstream.Request.ContentLength > 30000 {
		return fmt.Errorf("request payload is not 500 to 300000 bytes: %d", r.Upstream.Request.ContentLength)
	}
	contentType := r.Upstream.Request.Header.Get("Content-Type")
	if contentType != "application/x-www-form-urlencoded" {
		return fmt.Errorf("request content type is not application/x-www-form-urlencoded")
	}
	if err := r.Upstream.Request.ParseForm(); err != nil {
		return fmt.Errorf("failed to parse form: %v", err)
	}
	if r.Upstream.Request.FormValue("SAMLResponse") == "" {
		return fmt.Errorf("request from has no SAMLResponse field")
	}
	samlResponseBytes, err := base64.StdEncoding.DecodeString(r.Upstream.Request.FormValue("SAMLResponse"))
	if err != nil {
		return fmt.Errorf("failed to decode SAMLResponse: %v", err)
	}
	acsURL := ""
	s := string(samlResponseBytes)
	for _, elem := range []string{"Destination=\""} {
		i := strings.Index(s, elem)
		if i < 0 {
			continue
		}
		j := strings.Index(s[i+len(elem):], "\"")
		if j < 0 {
			continue
		}
		acsURL = s[i+len(elem) : i+len(elem)+j]
	}

	if acsURL == "" {
		return fmt.Errorf("failed to parse ACS URL")
	}

	if b.Config.Provider == "azure" {
		if !strings.Contains(r.Upstream.Request.Header.Get("Origin"), "login.microsoftonline.com") && !strings.Contains(r.Upstream.Request.Header.Get("Referer"), "windowsazure.com") {
			return fmt.Errorf("Origin does not contain login.microsoftonline.com and Referer is not windowsazure.com")
		}
	}

	sp, serviceProviderExists := b.serviceProviders[acsURL]
	if !serviceProviderExists {
		return fmt.Errorf("unsupported ACS URL %s", acsURL)
	}

	samlAssertions, err := sp.ParseXMLResponse(samlResponseBytes, []string{""})
	if err != nil {
		return fmt.Errorf("failed to ParseXMLResponse: %s", err)
	}

	m := make(map[string]interface{})

	for _, attrStatement := range samlAssertions.AttributeStatements {
		for _, attrEntry := range attrStatement.Attributes {
			if len(attrEntry.Values) == 0 {
				continue
			}
			if strings.HasSuffix(attrEntry.Name, "Attributes/MaxSessionDuration") {
				multiplier, err := strconv.Atoi(attrEntry.Values[0].Value)
				if err != nil {
					b.logger.Error(
						"Failed parsing Attributes/MaxSessionDuration",
						zap.String("request_id", r.ID),
						zap.String("error", err.Error()),
					)
					continue
				}
				m["exp"] = time.Now().Add(time.Duration(multiplier) * time.Second).Unix()
				continue
			}

			if strings.HasSuffix(attrEntry.Name, "identity/claims/displayname") {
				m["name"] = attrEntry.Values[0].Value
				continue
			}

			if strings.HasSuffix(attrEntry.Name, "identity/claims/emailaddress") {
				m["email"] = attrEntry.Values[0].Value
				continue
			}

			if strings.HasSuffix(attrEntry.Name, "identity/claims/identityprovider") {
				m["origin"] = attrEntry.Values[0].Value
				continue
			}

			if strings.HasSuffix(attrEntry.Name, "identity/claims/name") {
				m["sub"] = attrEntry.Values[0].Value
				continue
			}

			if strings.HasSuffix(attrEntry.Name, "Attributes/Role") {
				roles := []string{}
				for _, attrEntryElement := range attrEntry.Values {
					roles = append(roles, attrEntryElement.Value)
				}
				if len(roles) > 0 {
					m["roles"] = roles
				}
				continue
			}
		}
	}

	for _, k := range []string{"email", "name"} {
		if _, exists := m[k]; !exists {
			return fmt.Errorf("SAML authorization failed, mandatory %s attribute not found: %v", k, m)
		}
	}

	r.Response.Code = 200
	r.Response.Payload = m
	return nil
}
