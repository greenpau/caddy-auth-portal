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
	//"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/greenpau/caddy-auth-portal/pkg/errors"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"github.com/greenpau/go-identity/pkg/requests"
	uuid "github.com/satori/go.uuid"
	"go.uber.org/zap"
)

// Authenticate performs authentication.
func (b *Backend) Authenticate(r *requests.Request) error {
	reqPath := r.Upstream.BaseURL + path.Join(r.Upstream.BasePath, r.Upstream.Method, r.Upstream.Realm)
	r.Response.Code = http.StatusBadRequest

	var accessTokenExists, codeExists, stateExists, errorExists, loginHintExists bool
	var reqParamsState, reqParamsCode, reqParamsError, reqParamsLoginHint string
	reqParams := r.Upstream.Request.URL.Query()
	if _, exists := reqParams["access_token"]; exists {
		accessTokenExists = true
	}
	if _, exists := reqParams["code"]; exists {
		codeExists = true
		reqParamsCode = reqParams["code"][0]
	}
	if _, exists := reqParams["state"]; exists {
		stateExists = true
		reqParamsState = reqParams["state"][0]
	}
	if _, exists := reqParams["error"]; exists {
		errorExists = true
		reqParamsError = reqParams["error"][0]
	}
	if _, exists := reqParams["login_hint"]; exists {
		loginHintExists = true
		reqParamsLoginHint = reqParams["login_hint"][0]
	}

	if stateExists || errorExists || codeExists || accessTokenExists {
		b.logger.Debug(
			"received OAuth 2.0 response",
			zap.String("session_id", r.Upstream.SessionID),
			zap.String("request_id", r.ID),
			zap.Any("params", reqParams),
		)
		if errorExists {
			if v, exists := reqParams["error_description"]; exists {
				return errors.ErrBackendOauthAuthorizationFailedDetailed.WithArgs(reqParamsError, v[0])
			}
			return errors.ErrBackendOauthAuthorizationFailed.WithArgs(reqParamsError)
		}
		if codeExists && stateExists {
			// Received Authorization Code
			if b.state.exists(reqParamsState) {
				b.state.addCode(reqParamsState, reqParamsCode)
			} else {
				return errors.ErrBackendOauthAuthorizationStateNotFound
			}
			b.logger.Debug(
				"received OAuth 2.0 code and state from the authorization server",
				zap.String("session_id", r.Upstream.SessionID),
				zap.String("request_id", r.ID),
				zap.String("state", reqParamsState),
				zap.String("code", reqParamsCode),
			)

			reqRedirectURI := reqPath + "/authorization-code-callback"
			var accessToken map[string]interface{}
			var err error
			switch b.Config.Provider {
			case "facebook":
				accessToken, err = b.fetchFacebookAccessToken(reqRedirectURI, reqParamsState, reqParamsCode)
			default:
				accessToken, err = b.fetchAccessToken(reqRedirectURI, reqParamsState, reqParamsCode)
			}
			if err != nil {
				b.logger.Debug(
					"failed fetching OAuth 2.0 access token from the authorization server",
					zap.String("session_id", r.Upstream.SessionID),
					zap.String("request_id", r.ID),
					zap.Error(err),
				)
				return errors.ErrBackendOauthFetchAccessTokenFailed.WithArgs(err)
			}
			b.logger.Debug(
				"received OAuth 2.0 authorization server access token",
				zap.String("request_id", r.ID),
				zap.Any("token", accessToken),
			)

			var m map[string]interface{}

			switch b.Config.Provider {
			case "github", "gitlab", "facebook":
				m, err = b.fetchClaims(accessToken)
				if err != nil {
					return errors.ErrBackendOauthFetchClaimsFailed.WithArgs(err)
				}
			default:
				m, err = b.validateAccessToken(reqParamsState, accessToken)
				if err != nil {
					return errors.ErrBackendOauthValidateAccessTokenFailed.WithArgs(err)
				}
			}

			// Fetch subsequent user info, e.g. user groups.
			switch b.Config.Provider {
			case "google":
				if b.Config.ScopeExists(
					"https://www.googleapis.com/auth/cloud-identity.groups.readonly",
					"https://www.googleapis.com/auth/cloud-identity.groups",
				) {
					if err := b.fetchUserGroups(accessToken, m); err != nil {
						return errors.ErrBackendOauthFetchUserGroupsFailed.WithArgs(err)
					}
				}
			}

			r.Response.Payload = m
			r.Response.Code = http.StatusOK
			b.logger.Debug(
				"decoded claims from OAuth 2.0 authorization server access token",
				zap.String("request_id", r.ID),
				zap.Any("claims", m),
			)
			return nil
		}
		return errors.ErrBackendOauthResponseProcessingFailed
	}
	r.Response.Code = http.StatusFound
	state := uuid.NewV4().String()
	nonce := utils.GetRandomString(32)
	params := url.Values{}
	// CSRF Protection
	params.Set("state", state)
	if !b.disableNonce {
		// Server Side-Replay Protection
		params.Set("nonce", nonce)
	}
	if !b.disableScope {
		params.Set("scope", strings.Join(b.Config.Scopes, " "))
	}
	params.Set("redirect_uri", reqPath+"/authorization-code-callback")
	if !b.disableResponseType {
		params.Set("response_type", "code")
	}
	if loginHintExists {
		params.Set("login_hint", reqParamsLoginHint)
	}
	params.Set("client_id", b.Config.ClientID)

	r.Response.RedirectURL = b.authorizationURL + "?" + params.Encode()

	b.state.add(state, nonce)
	b.logger.Debug(
		"redirecting to OAuth 2.0 endpoint",
		zap.String("request_id", r.ID),
		zap.String("redirect_url", r.Response.RedirectURL),
	)
	return nil
}

func (b *Backend) fetchAccessToken(redirectURI, state, code string) (map[string]interface{}, error) {
	params := url.Values{}
	params.Set("client_id", b.Config.ClientID)
	params.Set("client_secret", b.Config.ClientSecret)
	if !b.disablePassGrantType {
		params.Set("grant_type", "authorization_code")
	}
	params.Set("state", state)
	params.Set("code", code)
	params.Set("redirect_uri", redirectURI)

	cli := &http.Client{
		Timeout: time.Second * 10,
	}

	cli, err := newBrowser()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", b.tokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	// Adjust !!!
	if b.enableAcceptHeader {
		req.Header.Set("Accept", "application/json")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(params.Encode())))

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
		"OAuth 2.0 access token response received",
		zap.Any("body", respBody),
		zap.String("redirect_uri", redirectURI),
	)

	data := make(map[string]interface{})
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, err
	}

	b.logger.Debug(
		"OAuth 2.0 access token response decoded",
		zap.Any("body", data),
	)

	if _, exists := data["error"]; exists {
		if v, exists := data["error_description"]; exists {
			return nil, errors.ErrBackendOauthGetAccessTokenFailedDetailed.WithArgs(data["error"].(string), v.(string))
		}
		switch data["error"].(type) {
		case string:
			return nil, errors.ErrBackendOauthGetAccessTokenFailed.WithArgs(data["error"].(string))
		default:
			return nil, errors.ErrBackendOauthGetAccessTokenFailed.WithArgs(data["error"])
		}
	}

	for k := range b.requiredTokenFields {
		if _, exists := data[k]; !exists {
			return nil, errors.ErrBackendAuthorizationServerResponseFieldNotFound.WithArgs(k)
		}
	}
	return data, nil
}

func newBrowser() (*http.Client, error) {
	/*
	   cj, err := cookiejar.New(nil)
	   if err != nil {
	       return nil, err
	   }
	*/
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &http.Client{
		//Jar:       cj,
		Timeout:   time.Second * 10,
		Transport: tr,
	}, nil
}

func (b *Backend) fetchFacebookAccessToken(redirectURI, state, code string) (map[string]interface{}, error) {
	params := url.Values{}
	params.Set("client_id", b.Config.ClientID)
	params.Set("client_secret", b.Config.ClientSecret)
	params.Set("code", code)
	params.Set("redirect_uri", redirectURI)

	cli := &http.Client{
		Timeout: time.Second * 10,
	}

	cli, err := newBrowser()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", b.tokenURL, nil)
	if err != nil {
		return nil, err
	}

	req.URL.RawQuery = params.Encode()

	// Adjust !!!
	if b.enableAcceptHeader {
		req.Header.Set("Accept", "application/json")
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
		"OAuth 2.0 access token response received",
		zap.Any("body", respBody),
	)

	data := make(map[string]interface{})
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, err
	}
	if _, exists := data["error"]; exists {
		if v, exists := data["error_description"]; exists {
			return nil, errors.ErrBackendOauthGetAccessTokenFailedDetailed.WithArgs(data["error"].(string), v.(string))
		}
		switch data["error"].(type) {
		case string:
			return nil, errors.ErrBackendOauthGetAccessTokenFailed.WithArgs(data["error"].(string))
		default:
			return nil, errors.ErrBackendOauthGetAccessTokenFailed.WithArgs(data["error"])
		}
	}

	for k := range b.requiredTokenFields {
		if _, exists := data[k]; !exists {
			return nil, errors.ErrBackendAuthorizationServerResponseFieldNotFound.WithArgs(k)
		}
	}
	return data, nil
}
