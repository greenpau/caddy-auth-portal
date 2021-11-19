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

package oauth2

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"go.uber.org/zap"
)

type googleResponse struct {
	Response struct {
		Groups []struct {
			DisplayName string `json:"displayName"`
		} `json:"groups"`
	} `json:"response"`
}

func (b *Backend) fetchUserGroups(tokenData, userData map[string]interface{}) error {
	var userURL string
	var req *http.Request
	var err error

	for _, k := range []string{"access_token"} {
		if _, exists := tokenData[k]; !exists {
			return fmt.Errorf("provider %s failed fetching user groups, token response has no %s field", b.Config.Provider, k)
		}
	}

	tokenString := tokenData["access_token"].(string)

	cli, err := newBrowser()
	if err != nil {
		return err
	}

	switch b.Config.Provider {
	case "google":
		userURL = "https://cloudidentity.googleapis.com/v1beta1/groups/-/memberships:getMembershipGraph?query="
		userURL += url.QueryEscape("'cloudidentity.googleapis.com/groups.discussion_forum' in labels && member_key_id='" + userData["email"].(string) + "'")

		req, err = http.NewRequest("GET", userURL, nil)
		if err != nil {
			return err
		}
		req.Header.Add("Authorization", "Bearer "+tokenString)
	default:
		return fmt.Errorf("provider %s is unsupported for fetching user groups", b.Config.Provider)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := cli.Do(req)
	if err != nil {
		return err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}

	b.logger.Debug(
		"User groups received",
		zap.Any("body", respBody),
		zap.String("url", userURL),
	)

	switch b.Config.Provider {
	case "google":
		var respParsed googleResponse
		err = json.Unmarshal(respBody, &respParsed)
		if err != nil {
			return err
		}
		userGroups := []string{}
		for _, group := range respParsed.Response.Groups {
			userGroups = append(userGroups, group.DisplayName)
		}

		if userRoles, exists := userData["roles"]; exists {
			userData["roles"] = append(userRoles.([]string), userGroups...)
		} else {
			userData["roles"] = userGroups
		}

	default:
		return fmt.Errorf("provider %s is unsupported for fetching user groups", b.Config.Provider)
	}

	return nil
}
