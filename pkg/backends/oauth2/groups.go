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
	"fmt"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
)

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
		userURL = "https://admin.googleapis.com/admin/directory/v1/groups?userKey=" + userData["email"].(string)
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

	return nil
}
