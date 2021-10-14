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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type userData struct {
	Groups []string `json:"groups,omitempty"`
}

func (b *Backend) fetchGithubUserInfo(params map[string]interface{}) (*userData, error) {
	var req *http.Request
	var reqMethod, reqURL, authToken string
	data := &userData{}
	reqURL = params["url"].(string)
	if _, exists := params["method"]; exists {
		reqMethod = params["method"].(string)
	} else {
		reqMethod = "GET"
	}
	authToken = params["token"].(string)

	// Create new http client instance.
	cli, err := newBrowser()
	if err != nil {
		return nil, err
	}
	req, err = http.NewRequest(reqMethod, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Add("Authorization", "token "+authToken)

	// Fetch data from the URL.
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	b.logger.Debug("Additional user data received", zap.String("url", reqURL), zap.Any("body", respBody))

	orgs := []map[string]interface{}{}
	if err := json.Unmarshal(respBody, &orgs); err != nil {
		return nil, err
	}
	for _, org := range orgs {
		if _, exists := org["login"]; !exists {
			continue
		}
		orgName := org["login"].(string)
		// Exclude org from processing if it does not match org filters.
		included := false
		for _, rp := range b.userOrgFilters {
			if rp.MatchString(orgName) {
				included = true
				break
			}
		}
		if !included {
			continue
		}
		data.Groups = append(data.Groups, fmt.Sprintf("github.com/%s/members", orgName))
	}

	b.logger.Debug(
		"Parsed additional user data",
		zap.String("url", reqURL),
		zap.Any("data", data),
	)

	return data, nil
}

func (b *Backend) fetchClaims(tokenData map[string]interface{}) (map[string]interface{}, error) {
	var userURL string
	var req *http.Request
	var err error

	for _, k := range []string{"access_token"} {
		if _, exists := tokenData[k]; !exists {
			return nil, fmt.Errorf("token response has no %s field", k)
		}
	}

	tokenString := tokenData["access_token"].(string)

	cli, err := newBrowser()
	if err != nil {
		return nil, err
	}

	// Configure user info URL.
	switch b.Config.Provider {
	case "github":
		userURL = "https://api.github.com/user"
	case "gitlab":
		userURL = b.userInfoURL
	case "facebook":
		userURL = "https://graph.facebook.com/me"
	}

	// Setup http request for the URL.
	switch b.Config.Provider {
	case "github", "gitlab":
		req, err = http.NewRequest("GET", userURL, nil)
		if err != nil {
			return nil, err
		}
	case "facebook":
		h := hmac.New(sha256.New, []byte(b.Config.ClientSecret))
		h.Write([]byte(tokenString))
		appSecretProof := hex.EncodeToString(h.Sum(nil))
		params := url.Values{}
		// See https://developers.facebook.com/docs/graph-api/reference/user/
		params.Set("fields", "id,first_name,last_name,name,email")
		params.Set("access_token", tokenString)
		params.Set("appsecret_proof", appSecretProof)
		req, err = http.NewRequest("GET", userURL, nil)
		if err != nil {
			return nil, err
		}
		req.URL.RawQuery = params.Encode()
	default:
		return nil, fmt.Errorf("provider %s is unsupported for fetching claims", b.Config.Provider)
	}

	req.Header.Set("Accept", "application/json")

	switch b.Config.Provider {
	case "github":
		req.Header.Add("Authorization", "token "+tokenString)
	case "gitlab":
		req.Header.Add("Authorization", "Bearer "+tokenString)
	}

	// Fetch data from the URL.
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	b.logger.Debug(
		"User profile received",
		zap.Any("body", respBody),
		zap.String("url", userURL),
	)

	data := make(map[string]interface{})
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, err
	}

	switch b.Config.Provider {
	case "gitlab":
		if _, exists := data["profile"]; !exists {
			return nil, fmt.Errorf("failed obtaining user profile with OAuth 2.0 access token, profile field not found")
		}
	case "github":
		if _, exists := data["message"]; exists {
			return nil, fmt.Errorf("failed obtaining user profile with OAuth 2.0 access token, error: %s", data["message"].(string))
		}
		if _, exists := data["login"]; !exists {
			return nil, fmt.Errorf("failed obtaining user profile with OAuth 2.0 access token, login field not found")
		}
	case "facebook":
		if _, exists := data["error"]; exists {
			switch data["error"].(type) {
			case map[string]interface{}:
				var fbError strings.Builder
				errMsg := data["error"].(map[string]interface{})
				if v, exists := errMsg["code"]; exists {
					errCode := strconv.FormatFloat(v.(float64), 'f', 0, 64)
					fbError.WriteString("code=" + errCode)
				}
				for _, k := range []string{"fbtrace_id", "message", "type"} {
					if v, exists := errMsg[k]; exists {
						fbError.WriteString(", " + k + "=" + v.(string))
					}
				}
				return nil, fmt.Errorf("failed obtaining user profile with OAuth 2.0 access token, error: %s", fbError.String())
			default:
				return nil, fmt.Errorf("failed obtaining user profile with OAuth 2.0 access token, error: %v", data["error"])
			}
		}
		for _, k := range []string{"name", "id"} {
			if _, exists := data[k]; !exists {
				return nil, fmt.Errorf("failed obtaining user profile with OAuth 2.0 access token, field %s not found, data: %v", k, data)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported provider: %s", b.Config.Provider)
	}

	m := make(map[string]interface{})
	var userGroups []string
	m["origin"] = userURL
	switch b.Config.Provider {
	case "github":
		if _, exists := data["login"]; exists {
			switch v := data["login"].(type) {
			case string:
				m["sub"] = "github.com/" + v
			}
		}
		if _, exists := data["name"]; exists {
			switch v := data["name"].(type) {
			case string:
				m["name"] = v
			}
		}
		if _, exists := data["avatar_url"]; exists {
			switch v := data["avatar_url"].(type) {
			case string:
				m["picture"] = v
			}
		}
		metadata := make(map[string]interface{})
		if v, exists := data["id"]; exists {
			metadata["id"] = v
		}
		m["metadata"] = metadata

		if orgURL, exists := data["organizations_url"]; exists && len(b.userOrgFilters) > 0 {
			params := map[string]interface{}{
				"url":      orgURL.(string),
				"method":   "GET",
				"token":    tokenString,
				"username": data["login"].(string),
			}
			userData, err := b.fetchGithubUserInfo(params)
			if err != nil {
				b.logger.Error(
					"Failed extracting user org data",
					zap.String("backend_name", b.Config.Name),
					zap.Error(err),
				)
			} else {
				userGroups = append(userGroups, userData.Groups...)
				b.logger.Debug(
					"Successfully extracted user org data",
					zap.String("backend_name", b.Config.Name),
					zap.Any("extracted", userData),
				)
			}
		}

		b.logger.Debug(
			"Extracted UserInfo endpoint data",
			zap.String("backend_name", b.Config.Name),
			zap.Any("inputted", data),
			zap.Any("extracted", m),
		)

	case "gitlab":
		for _, k := range []string{"name", "picture", "profile", "email"} {
			if _, exists := data[k]; !exists {
				continue
			}
			switch v := data[k].(type) {
			case string:
				switch k {
				case "profile":
					m["sub"] = v
				default:
					m[k] = v
				}
			}
		}
		if len(b.userGroupFilters) > 0 {
			if _, exists := data["groups"]; exists {
				switch groups := data["groups"].(type) {
				case []interface{}:
					for _, v := range groups {
						switch groupName := v.(type) {
						case string:
							for _, rp := range b.userGroupFilters {
								if !rp.MatchString(groupName) {
									continue
								}
								userGroups = append(userGroups, b.serverName+"/"+groupName)
								break
							}
						}
					}
				}
			}
		}
		b.logger.Debug(
			"Extracted UserInfo endpoint data",
			zap.String("backend_name", b.Config.Name),
			zap.Any("data", m),
		)
	case "facebook":
		if v, exists := data["email"]; exists {
			m["email"] = v
		}
		m["sub"] = data["id"]
		m["name"] = data["name"]
	}

	if len(userGroups) > 0 {
		m["groups"] = userGroups
	}
	return m, nil
}
