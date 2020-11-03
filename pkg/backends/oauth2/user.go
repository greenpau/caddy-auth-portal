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

package oauth2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	jwtclaims "github.com/greenpau/caddy-auth-jwt/pkg/claims"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (b *Backend) fetchClaims(tokenData map[string]interface{}) (*jwtclaims.UserClaims, error) {
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

	switch b.Provider {
	case "github":
		userURL = "https://api.github.com/user"
		req, err = http.NewRequest("GET", userURL, nil)
		if err != nil {
			return nil, err
		}
	case "facebook":
		h := hmac.New(sha256.New, []byte(b.ClientSecret))
		h.Write([]byte(tokenString))
		appSecretProof := hex.EncodeToString(h.Sum(nil))
		userURL = "https://graph.facebook.com/me"
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
		return nil, fmt.Errorf("provider %s is unsupported for fetching claims", b.Provider)
	}

	req.Header.Set("Accept", "application/json")

	switch b.Provider {
	case "github":
		req.Header.Add("Authorization", "token "+tokenString)
	}

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

	switch b.Provider {
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
		return nil, fmt.Errorf("unsupported provider: %s", b.Provider)
	}

	// Create new claims
	claims := &jwtclaims.UserClaims{
		//ID:        tokenID,
		Origin:    userURL,
		ExpiresAt: time.Now().Add(time.Duration(b.TokenProvider.TokenLifetime) * time.Second).Unix(),
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Add(10 * time.Minute * -1).Unix(),
	}

	switch b.Provider {
	case "github":
		if _, exists := data["login"]; exists {
			claims.Subject = "github.com/" + data["login"].(string)
		}
		if _, exists := data["name"]; !exists {
			claims.Name = data["name"].(string)
		}
	case "facebook":
		if v, exists := data["email"]; exists {
			claims.Email = v.(string)
		}
		claims.Subject = data["id"].(string)
		claims.Name = data["name"].(string)
	}

	if len(claims.Roles) < 1 {
		claims.Roles = []string{"anonymous", "guest", "everyone"}
	}

	return claims, nil
}
