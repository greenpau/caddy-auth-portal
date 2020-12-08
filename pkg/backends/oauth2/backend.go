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
	"crypto/rsa"
	//"encoding/base64"
	"encoding/json"
	"fmt"
	jwtclaims "github.com/greenpau/caddy-auth-jwt/pkg/claims"
	jwtconfig "github.com/greenpau/caddy-auth-jwt/pkg/config"
	"github.com/greenpau/caddy-auth-portal/pkg/errors"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"github.com/greenpau/go-identity"
	"github.com/satori/go.uuid"
	"go.uber.org/zap"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Backend represents authentication provider with OAuth 2.0 backend.
type Backend struct {
	Name     string `json:"name,omitempty"`
	Method   string `json:"method,omitempty"`
	Realm    string `json:"realm,omitempty"`
	Provider string `json:"provider,omitempty"`

	DomainName        string `json:"domain_name,omitempty"`
	ClientID          string `json:"client_id,omitempty"`
	ClientSecret      string `json:"client_secret,omitempty"`
	ServerID          string `json:"server_id,omitempty"`
	AppSecret         string `json:"app_secret,omitempty"`
	TenantID          string `json:"tenant_id,omitempty"`
	IdentityTokenName string `json:"identity_token_name,omitempty"`

	Scopes []string `json:"scopes,omitempty"`

	UserRoleMapList []map[string]interface{} `json:"user_roles,omitempty"`

	// The URL to OAuth 2.0 Custom Authorization Server.
	BaseAuthURL string `json:"base_auth_url,omitempty"`
	// The URL to OAuth 2.0 metadata related to your Custom Authorization Server.
	MetadataURL string `json:"metadata_url,omitempty"`

	// Stores data from .well-known/openid-configuration
	metadata               map[string]interface{}
	keys                   map[string]*JwksKey
	publicKeys             map[string]*rsa.PublicKey
	authorizationURL       string
	tokenURL               string
	keysURL                string
	lastKeyFetch           time.Time
	keyFetchAttempts       int
	disableKeyVerification bool
	disablePassGrantType   bool
	disableResponseType    bool
	disableNonce           bool
	disableScope           bool
	enableAcceptHeader     bool
	enableBodyDecoder      bool
	requiredTokenFields    map[string]interface{}
	// Stores cached state IDs
	state *stateManager

	TokenProvider *jwtconfig.CommonTokenConfig `json:"-"`
	logger        *zap.Logger
}

// NewDatabaseBackend return an instance of authentication provider
// with OAuth 2.0 backend.
func NewDatabaseBackend() *Backend {
	b := &Backend{
		Method:        "oauth2",
		TokenProvider: jwtconfig.NewCommonTokenConfig(),
		state:         newStateManager(),
		keys:          make(map[string]*JwksKey),
		publicKeys:    make(map[string]*rsa.PublicKey),
		requiredTokenFields: map[string]interface{}{
			"access_token": true,
			"id_token":     true,
		},
	}
	go manageStateManager(b.state)
	return b
}

// ConfigureAuthenticator configures backend authenticator.
func (b *Backend) ConfigureAuthenticator() error {
	if b.Realm == "" {
		return errors.ErrBackendRealmNotFound.WithArgs(b.Provider)
	}
	if b.ClientID == "" {
		return errors.ErrBackendClientIDNotFound.WithArgs(b.Provider)
	}
	if b.ClientSecret == "" {
		return errors.ErrBackendClientSecretNotFound.WithArgs(b.Provider)
	}

	if len(b.Scopes) < 1 {
		b.Scopes = []string{"openid", "email", "profile"}
	}

	switch b.IdentityTokenName {
	case "":
		b.IdentityTokenName = "id_token"
	case "id_token", "access_token":
	default:
		return errors.ErrBackendInvalidIdentityTokenName.WithArgs(b.IdentityTokenName, b.Provider)
	}

	switch b.Provider {
	case "okta":
		if b.ServerID == "" {
			return errors.ErrBackendServerIDNotFound.WithArgs(b.Provider)
		}
		if b.DomainName == "" {
			return errors.ErrBackendAppNameNotFound.WithArgs(b.Provider)
		}
		if b.BaseAuthURL == "" {
			b.BaseAuthURL = fmt.Sprintf(
				"https://%s/oauth2/%s/",
				b.DomainName, b.ServerID,
			)
			b.MetadataURL = b.BaseAuthURL + ".well-known/openid-configuration?client_id=" + b.ClientID
		}
	case "google":
		if b.BaseAuthURL == "" {
			b.BaseAuthURL = "https://accounts.google.com/o/oauth2/v2/"
			b.MetadataURL = "https://accounts.google.com/.well-known/openid-configuration"
		}
	case "github":
		if b.BaseAuthURL == "" {
			b.BaseAuthURL = "https://github.com/login/oauth/"
		}
		b.authorizationURL = "https://github.com/login/oauth/authorize"
		b.tokenURL = "https://github.com/login/oauth/access_token"
		b.disableKeyVerification = true
		b.disablePassGrantType = true
		b.disableResponseType = true
		b.disableNonce = true
		b.enableAcceptHeader = true
		b.requiredTokenFields = map[string]interface{}{
			"access_token": true,
		}
	case "azure":
		if b.TenantID == "" {
			b.TenantID = "common"
		}
		if b.BaseAuthURL == "" {
			b.BaseAuthURL = "https://login.microsoftonline.com/" + b.TenantID + "/oauth2/v2.0/"
			b.MetadataURL = "https://login.microsoftonline.com/" + b.TenantID + "/v2.0/.well-known/openid-configuration"
		}
	case "facebook":
		if b.BaseAuthURL == "" {
			b.BaseAuthURL = "https://www.facebook.com/v8.0/dialog/"
		}
		b.authorizationURL = "https://www.facebook.com/v8.0/dialog/oauth"
		b.tokenURL = "https://graph.facebook.com/v8.0/oauth/access_token"
		b.disableKeyVerification = true
		b.disablePassGrantType = true
		b.disableResponseType = true
		b.disableNonce = true
		b.enableAcceptHeader = true
		b.disableScope = true
		b.requiredTokenFields = map[string]interface{}{
			"access_token": true,
		}
	case "generic":
	case "":
		return errors.ErrBackendOauthProviderNotFound.WithArgs(b.Provider)
	default:
		return errors.ErrBackendUnsupportedProvider.WithArgs(b.Provider)
	}

	if b.BaseAuthURL == "" {
		return errors.ErrBackendOauthAuthorizationURLNotFound.WithArgs(b.Provider)
	}

	if b.authorizationURL == "" {
		if err := b.fetchMetadataURL(); err != nil {
			return errors.ErrBackendOauthMetadataFetchFailed.WithArgs(err)
		}
	}

	if !b.disableKeyVerification {
		if err := b.fetchKeysURL(); err != nil {
			return errors.ErrBackendOauthKeyFetchFailed.WithArgs(err)
		}
	}

	b.logger.Info(
		"successfully configured OAuth 2.0 backend",
		zap.String("provider", b.Provider),
		zap.String("client_id", b.ClientID),
		zap.String("server_id", b.ServerID),
		zap.String("domain_name", b.DomainName),
		zap.Any("metadata", b.metadata),
		zap.Any("jwks_keys", b.keys),
	)

	return nil
}

// ValidateConfig checks whether Backend has mandatory configuration.
func (b *Backend) ValidateConfig() error {
	return nil
}

// Authenticate performs authentication.
func (b *Backend) Authenticate(opts map[string]interface{}) (map[string]interface{}, error) {
	r := opts["request"].(*http.Request)
	reqID := opts["request_id"].(string)
	reqPath := opts["request_path"].(string)
	resp := make(map[string]interface{})
	resp["code"] = 400

	var accessTokenExists, codeExists, stateExists, errorExists bool
	var reqParamsState, reqParamsCode, reqParamsError string
	reqParams := r.URL.Query()
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

	if stateExists || errorExists || codeExists || accessTokenExists {
		b.logger.Debug(
			"received OAuth 2.0 response",
			zap.String("request_id", reqID),
			zap.Any("params", reqParams),
		)
		if errorExists {
			if v, exists := reqParams["error_description"]; exists {
				return resp, errors.ErrBackendOauthAuthorizationFailedDetailed.WithArgs(reqParamsError, v[0])
			}
			return resp, errors.ErrBackendOauthAuthorizationFailed.WithArgs(reqParamsError)
		}
		if codeExists && stateExists {
			// Received Authorization Code
			if b.state.exists(reqParamsState) {
				b.state.addCode(reqParamsState, reqParamsCode)
			} else {
				return resp, errors.ErrBackendOauthAuthorizationStateNotFound
			}
			reqRedirectURI := utils.GetCurrentBaseURL(r) + reqPath + "/authorization-code-callback"
			var accessToken map[string]interface{}
			var err error
			switch b.Provider {
			case "facebook":
				accessToken, err = b.fetchFacebookAccessToken(reqRedirectURI, reqParamsState, reqParamsCode)
			default:
				accessToken, err = b.fetchAccessToken(reqRedirectURI, reqParamsState, reqParamsCode)
			}
			if err != nil {
				return resp, errors.ErrBackendOauthFetchAccessTokenFailed.WithArgs(err)
			}
			b.logger.Debug(
				"received OAuth 2.0 authorization server access token",
				zap.String("request_id", reqID),
				zap.Any("token", accessToken),
			)

			var claims *jwtclaims.UserClaims
			switch b.Provider {
			case "github", "facebook":
				claims, err = b.fetchClaims(accessToken)
				if err != nil {
					return resp, errors.ErrBackendOauthFetchClaimsFailed.WithArgs(err)
				}
			default:
				claims, err = b.validateAccessToken(reqParamsState, accessToken)
				if err != nil {
					return resp, errors.ErrBackendOauthValidateAccessTokenFailed.WithArgs(err)
				}
			}

			// Add additional roles, if necessary
			b.supplementClaims(claims)
			resp["claims"] = claims
			b.logger.Debug(
				"received OAuth 2.0 authorization server access token",
				zap.String("request_id", reqID),
				zap.Any("claims", claims),
			)
			return resp, nil
		}
		return resp, errors.ErrBackendOauthResponseProcessingFailed
	}

	resp["code"] = 200
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
		params.Set("scope", strings.Join(b.Scopes, " "))
	}
	params.Set("redirect_uri", utils.GetCurrentBaseURL(r)+reqPath+"/authorization-code-callback")
	if !b.disableResponseType {
		params.Set("response_type", "code")
	}
	params.Set("client_id", b.ClientID)
	resp["redirect_url"] = b.authorizationURL + "?" + params.Encode()
	b.state.add(state, nonce)
	b.logger.Debug(
		"redirecting to OAuth 2.0 endpoint",
		zap.String("request_id", reqID),
		zap.String("redirect_url", resp["redirect_url"].(string)),
	)
	return resp, nil
}

// Validate checks whether Backend is functional.
func (b *Backend) Validate() error {
	if err := b.ValidateConfig(); err != nil {
		return err
	}
	if b.logger == nil {
		return errors.ErrBackendLoggerNotFound.WithArgs("OAuth 2.0")
	}

	b.logger.Info("successfully validated OAuth 2.0 backend")
	return nil
}

// GetRealm return authentication realm.
func (b *Backend) GetRealm() string {
	return b.Realm
}

// GetName return the name associated with this backend.
func (b *Backend) GetName() string {
	return b.Name
}

// ConfigureTokenProvider configures TokenProvider.
func (b *Backend) ConfigureTokenProvider(upstream *jwtconfig.CommonTokenConfig) error {
	if upstream == nil {
		return errors.ErrBackendTokenProviderNotFound
	}
	if b.TokenProvider == nil {
		b.TokenProvider = jwtconfig.NewCommonTokenConfig()
	}
	if b.TokenProvider.TokenSecret == "" {
		b.TokenProvider.TokenSecret = upstream.TokenSecret
	}
	if b.TokenProvider.TokenOrigin == "" {
		b.TokenProvider.TokenOrigin = upstream.TokenOrigin
	}
	b.TokenProvider.TokenLifetime = upstream.TokenLifetime
	b.TokenProvider.TokenName = upstream.TokenName
	return nil
}

// ConfigureLogger configures backend with the same logger as its user.
func (b *Backend) ConfigureLogger(logger *zap.Logger) error {
	if logger == nil {
		return errors.ErrBackendUpstreamLoggerNotFound
	}
	b.logger = logger
	return nil
}

// GetMethod returns the authentication method associated with this backend.
func (b *Backend) GetMethod() string {
	return b.Method
}

func (b *Backend) fetchMetadataURL() error {
	resp, err := http.Get(b.MetadataURL)
	if err != nil {
		return err
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	if err := json.Unmarshal(respBody, &b.metadata); err != nil {
		return err
	}
	for _, k := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		if _, exists := b.metadata[k]; !exists {
			return errors.ErrBackendOauthMetadataFieldNotFound.WithArgs(k, b.Provider)
		}
	}
	b.authorizationURL = b.metadata["authorization_endpoint"].(string)
	b.tokenURL = b.metadata["token_endpoint"].(string)
	b.keysURL = b.metadata["jwks_uri"].(string)
	return nil
}

func (b *Backend) countFetchKeysAttempt() {
	b.lastKeyFetch = time.Now().UTC()
	b.keyFetchAttempts++
	return
}

func (b *Backend) fetchKeysURL() error {
	if b.keyFetchAttempts > 3 {
		timeDiff := time.Now().UTC().Sub(b.lastKeyFetch).Minutes()
		if timeDiff < 5 {
			return errors.ErrBackendOauthJwksKeysTooManyAttempts
		}
		b.lastKeyFetch = time.Now().UTC()
		b.keyFetchAttempts = 0
	}
	b.countFetchKeysAttempt()
	resp, err := http.Get(b.keysURL)
	if err != nil {
		return err
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	data := make(map[string]interface{})

	if err := json.Unmarshal(respBody, &data); err != nil {
		return err
	}

	if _, exists := data["keys"]; !exists {
		return errors.ErrBackendOauthJwksResponseKeysNotFound
	}

	jwksJSON, err := json.Marshal(data["keys"])
	if err != nil {
		return errors.ErrBackendOauthJwksKeysParseFailed.WithArgs(err)
	}

	keys := []*JwksKey{}
	if err := json.Unmarshal(jwksJSON, &keys); err != nil {
		return err
	}

	if len(keys) < 1 {
		return errors.ErrBackendOauthJwksKeysNotFound
	}

	for _, k := range keys {
		if err := k.Validate(); err != nil {
			return errors.ErrBackendOauthJwksInvalidKey.WithArgs(err)
		}
		b.keys[k.KeyID] = k
		b.publicKeys[k.KeyID] = k.publicKey
	}

	return nil
}

func (b *Backend) fetchAccessToken(redirectURI, state, code string) (map[string]interface{}, error) {
	params := url.Values{}
	params.Set("client_id", b.ClientID)
	params.Set("client_secret", b.ClientSecret)
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

func (b *Backend) supplementClaims(claims *jwtclaims.UserClaims) {
	if len(b.UserRoleMapList) < 1 {
		return
	}

	var userID string

	switch b.Provider {
	case "github":
		if claims.Subject == "" {
			return
		}
		userID = claims.Subject
	default:
		if claims.Email == "" {
			return
		}
		userID = claims.Email
	}

	roles := []string{}
	roleMap := make(map[string]interface{})
	for _, roleName := range claims.Roles {
		roleMap[roleName] = true
		roles = append(roles, roleName)
	}

	for _, entry := range b.UserRoleMapList {
		if entry == nil {
			continue
		}
		entryEmail := entry["email"].(string)
		entryMatchType := entry["match"].(string)

		switch entryMatchType {
		case "regex":
			// Perform regex match
			matched, err := regexp.MatchString(entryEmail, userID)
			if err != nil {
				continue
			}
			if !matched {
				continue
			}
		case "exact":
			// Perform exact match
			if entryEmail != userID {
				continue
			}
		default:
			continue
		}
		entryRoles := entry["roles"].([]interface{})
		for _, r := range entryRoles {
			roleName := r.(string)
			if _, exists := roleMap[roleName]; !exists {
				roleMap[roleName] = true
				roles = append(roles, roleName)
			}
		}
	}
	claims.Roles = roles
}

func newBrowser() (*http.Client, error) {
	/*
		cj, err := cookiejar.New(nil)
		if err != nil {
			return nil, err
		}
	*/
	tr := &http.Transport{
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
	params.Set("client_id", b.ClientID)
	params.Set("client_secret", b.ClientSecret)
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

// Do performs the requested operation.
func (b *Backend) Do(opts map[string]interface{}) error {
	op := opts["name"].(string)
	switch op {
	case "password_change":
		return fmt.Errorf("Password change operation is not available")
	}
	return fmt.Errorf("Unsupported backend operation")
}

// GetPublicKeys return a list of public keys associated with a user.
func (b *Backend) GetPublicKeys(opts map[string]interface{}) ([]*identity.PublicKey, error) {
	return nil, fmt.Errorf("Unsupported backend operation")
}

// GetMfaTokens return a list of MFA tokens associated with a user.
func (b *Backend) GetMfaTokens(opts map[string]interface{}) ([]*identity.MfaToken, error) {
	return nil, fmt.Errorf("Unsupported backend operation")
}
