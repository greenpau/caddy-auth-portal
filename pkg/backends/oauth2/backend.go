package oauth2

import (
	"encoding/json"
	"fmt"
	"github.com/greenpau/caddy-auth-jwt"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"github.com/satori/go.uuid"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// Backend represents authentication provider with OAuth 2.0 backend.
type Backend struct {
	Name     string `json:"name,omitempty"`
	Method   string `json:"method,omitempty"`
	Realm    string `json:"realm,omitempty"`
	Provider string `json:"provider,omitempty"`

	DomainName   string `json:"domain_name,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	ServerID     string `json:"server_id,omitempty"`

	// The URL to OAuth 2.0 Custom Authorization Server.
	BaseAuthURL string `json:"base_auth_url,omitempty"`
	// The URL to OAuth 2.0 metadata related to your Custom Authorization Server.
	MetadataURL string `json:"metadata_url,omitempty"`

	// Stores data from .well-known/oauth-authorization-server
	metadata         map[string]interface{}
	authorizationURL string
	tokenURL         string
	// Stores cached state IDs
	state *stateManager

	TokenProvider *jwt.TokenProviderConfig `json:"-"`
	logger        *zap.Logger
}

// NewDatabaseBackend return an instance of authentication provider
// with OAuth 2.0 backend.
func NewDatabaseBackend() *Backend {
	b := &Backend{
		Method:        "oauth2",
		TokenProvider: jwt.NewTokenProviderConfig(),
		state:         newStateManager(),
	}
	go manageStateManager(b.state)
	return b
}

// ConfigureAuthenticator configures backend authenticator.
func (b *Backend) ConfigureAuthenticator() error {
	if b.Realm == "" {
		return fmt.Errorf("no realm found for provider %s", b.Provider)
	}
	if b.ClientID == "" {
		return fmt.Errorf("no client_id found for provider %s", b.Provider)
	}
	if b.ClientSecret == "" {
		return fmt.Errorf("no client_secret found for provider %s", b.Provider)
	}

	switch b.Provider {
	case "okta":
		if b.ServerID == "" {
			return fmt.Errorf("no server_id found for provider %s", b.Provider)
		}
		if b.DomainName == "" {
			return fmt.Errorf("no application name found for provider %s", b.Provider)
		}
		if b.BaseAuthURL == "" {
			b.BaseAuthURL = fmt.Sprintf(
				"https://%s/oauth2/%s/",
				b.DomainName, b.ServerID,
			)
			b.MetadataURL = b.BaseAuthURL + ".well-known/oauth-authorization-server?client_id=" + b.ClientID
		}
	case "":
		return fmt.Errorf("no OAuth 2.0 provider found for provider %s", b.Provider)
	default:
		return fmt.Errorf("unsupported OAuth 2.0 provider %s", b.Provider)
	}

	if b.BaseAuthURL == "" {
		return fmt.Errorf("authorization URL not found for provider %s", b.Provider)
	}

	if err := b.fetchMetadataURL(); err != nil {
		return fmt.Errorf("failed to fetch metdata for OAuth 2.0 authorization server: %s", err)
	}

	b.logger.Info(
		"successfully configured OAuth 2.0 backend",
		zap.String("provider", b.Provider),
		zap.String("client_id", b.ClientID),
		zap.String("server_id", b.ServerID),
		zap.String("domain_name", b.DomainName),
		zap.Any("metadata", b.metadata),
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
				return resp, fmt.Errorf("failed OAuth 2.0 authorization flow, error: %s, description: %s", reqParamsError, v[0])
			} else {
				return resp, fmt.Errorf("failed OAuth 2.0 authorization flow, error: %s", reqParamsError)
			}
		}
		if codeExists && stateExists {
			// Received Authorization Code
			if b.state.exists(reqParamsState) {
				b.state.addCode(reqParamsState, reqParamsCode)
			} else {
				return resp, fmt.Errorf("OAuth 2.0 authorization state %s not found")
			}
			reqRedirectURI := utils.GetCurrentBaseURL(r) + reqPath + "/authorization-code-callback"
			accessToken, err := b.fetchAccessToken(reqRedirectURI, reqParamsState, reqParamsCode)
			if err != nil {
				return resp, fmt.Errorf("failed fetching OAuth 2.0 access token: %s", err)
			}
			b.logger.Debug(
				"received OAuth 2.0 authorization server access token",
				zap.String("request_id", reqID),
				zap.Any("token", accessToken),
			)

			// TODO: validate token
			// TODO: validate nonce
			// TODO: issue token

			return resp, fmt.Errorf("got OAuth 2.0 authorization code")
		}
		return resp, fmt.Errorf("unable to process OAuth 2.0 response")
	} else {
		resp["code"] = 200
		state := uuid.NewV4().String()
		nonce := utils.GetRandomString(12)
		params := url.Values{}
		// CSRF Protection
		params.Set("state", state)
		// Server Side-Replay Protection
		params.Set("nonce", nonce)
		params.Set("scope", "openid email profile groups")
		params.Set("redirect_uri", utils.GetCurrentBaseURL(r)+reqPath+"/authorization-code-callback")
		params.Set("response_type", "code")
		params.Set("client_id", b.ClientID)
		// Any combination of code, token, and id_token. The combination determines the flow.
		resp["redirect_url"] = b.authorizationURL + "?" + params.Encode()
		b.state.add(state, nonce)
		b.logger.Debug(
			"redirecting to OAuth 2.0 endpoint",
			zap.String("request_id", reqID),
			zap.String("redirect_url", resp["redirect_url"].(string)),
		)
		return resp, nil
	}

	/*

		if r.ContentLength > 30000 {
			return resp, fmt.Errorf("Request payload exceeded the limit of 30,000 bytes: %d", r.ContentLength)
		}
		if r.ContentLength < 500 {
			return resp, fmt.Errorf("Request payload is too small: %d", r.ContentLength)
		}
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/x-www-form-urlencoded" {
			return resp, fmt.Errorf("Request content type is not application/x-www-form-urlencoded")
		}
		if err := r.ParseForm(); err != nil {
			return resp, fmt.Errorf("Failed to parse form: %s", err)
		}
		if r.FormValue("OAuth 2.0Response") == "" {
			return resp, fmt.Errorf("Request payload has no OAuth 2.0Response field")
		}
		samlResponseBytes, err := base64.StdEncoding.DecodeString(r.FormValue("OAuth 2.0Response"))
		if err != nil {
			return resp, err
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
			return resp, fmt.Errorf("Failed to parse ACS URL")
		}

		if b.Provider == "azure" {
			if !strings.Contains(r.Header.Get("Origin"), "login.microsoftonline.com") &&
				!strings.Contains(r.Header.Get("Referer"), "windowsazure.com") {
				return resp, fmt.Errorf("Origin does not contain login.microsoftonline.com and Referer is not windowsazure.com")
			}
		}

		sp, serviceProviderExists := b.ServiceProviders[acsURL]
		if !serviceProviderExists {
			return resp, fmt.Errorf("Unsupported ACS URL %s", acsURL)
		}

		samlAssertions, err := sp.ParseXMLResponse(samlResponseBytes, []string{""})
		if err != nil {
			return resp, fmt.Errorf("Failed to ParseXMLResponse: %s", err)
		}

		claims := &jwt.UserClaims{}

		foundAttr := make(map[string]interface{})

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
							zap.String("request_id", reqID),
							zap.String("error", err.Error()),
						)
						continue
					}
					claims.ExpiresAt = time.Now().Add(time.Duration(multiplier) * time.Second).Unix()
					foundAttr["exp"] = true
					continue
				}

				if strings.HasSuffix(attrEntry.Name, "identity/claims/displayname") {
					claims.Name = attrEntry.Values[0].Value
					continue
				}

				if strings.HasSuffix(attrEntry.Name, "identity/claims/emailaddress") {
					claims.Email = attrEntry.Values[0].Value
					continue
				}

				if strings.HasSuffix(attrEntry.Name, "identity/claims/identityprovider") {
					claims.Origin = attrEntry.Values[0].Value
					continue
				}

				if strings.HasSuffix(attrEntry.Name, "identity/claims/name") {
					claims.Subject = attrEntry.Values[0].Value
					continue
				}

				if strings.HasSuffix(attrEntry.Name, "Attributes/Role") {
					for _, attrEntryElement := range attrEntry.Values {
						claims.Roles = append(claims.Roles, attrEntryElement.Value)
					}
					continue
				}
			}
		}

		if claims.Email == "" || claims.Name == "" {
			return resp, fmt.Errorf("The Azure AD authorization failed, mandatory attributes not found: %v", claims)
		}

		if len(claims.Roles) == 0 {
			claims.Roles = append(claims.Roles, "anonymous")
		}

		if claims.Origin == "" {
			claims.Origin = b.TokenProvider.TokenOrigin
		}

		if _, found := foundAttr["exp"]; !found {
			claims.ExpiresAt = time.Now().Add(time.Duration(b.TokenProvider.TokenLifetime) * time.Second).Unix()
		}

		resp["claims"] = claims
		return resp, nil

	*/

	return resp, fmt.Errorf("unsupported yet")
}

// Validate checks whether Backend is functional.
func (b *Backend) Validate() error {
	if err := b.ValidateConfig(); err != nil {
		return err
	}
	if b.logger == nil {
		return fmt.Errorf("OAuth 2.0 backend logger is nil")
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
func (b *Backend) ConfigureTokenProvider(upstream *jwt.TokenProviderConfig) error {
	if upstream == nil {
		return fmt.Errorf("upstream token provider is nil")
	}
	if b.TokenProvider == nil {
		b.TokenProvider = jwt.NewTokenProviderConfig()
	}
	if b.TokenProvider.TokenName == "" {
		b.TokenProvider.TokenName = upstream.TokenName
	}
	if b.TokenProvider.TokenSecret == "" {
		b.TokenProvider.TokenSecret = upstream.TokenSecret
	}
	if b.TokenProvider.TokenIssuer == "" {
		b.TokenProvider.TokenIssuer = upstream.TokenIssuer
	}
	if b.TokenProvider.TokenOrigin == "" {
		b.TokenProvider.TokenOrigin = upstream.TokenOrigin
	}
	if b.TokenProvider.TokenLifetime == 0 {
		b.TokenProvider.TokenLifetime = upstream.TokenLifetime
	}
	return nil
}

// ConfigureLogger configures backend with the same logger as its user.
func (b *Backend) ConfigureLogger(logger *zap.Logger) error {
	if logger == nil {
		return fmt.Errorf("upstream logger is nil")
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
	for _, k := range []string{"authorization_endpoint", "token_endpoint"} {
		if _, exists := b.metadata[k]; !exists {
			return fmt.Errorf("metadata has no %s field", k)
		}
	}
	b.authorizationURL = b.metadata["authorization_endpoint"].(string)
	b.tokenURL = b.metadata["token_endpoint"].(string)
	return nil
}

func (b *Backend) fetchAccessToken(redirectURI, state, code string) (map[string]interface{}, error) {
	params := url.Values{}
	params.Set("client_id", b.ClientID)
	params.Set("client_secret", b.ClientSecret)
	params.Set("grant_type", "authorization_code")
	params.Set("state", state)
	params.Set("code", code)
	params.Set("redirect_uri", redirectURI)
	resp, err := http.Post(b.tokenURL, "application/x-www-form-urlencoded", strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	data := make(map[string]interface{})
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, err
	}
	if _, exists := data["error"]; exists {
		if v, exists := data["error_description"]; exists {
			return nil, fmt.Errorf("failed obtaining OAuth 2.0 access token, error: %s, description: %s", data["error"].(string), v.(string))
		} else {
			return nil, fmt.Errorf("failed obtaining OAuth 2.0 access token, error: %s", data["error"].(string))
		}
	}
	for _, k := range []string{"access_token", "id_token"} {
		if _, exists := data[k]; !exists {
			return nil, fmt.Errorf("authorization server response has no %s field", k)
		}
	}
	return data, nil
}
