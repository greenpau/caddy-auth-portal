package forms

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"github.com/google/uuid"
	"github.com/greenpau/caddy-auth-jwt"
	"github.com/greenpau/caddy-auth-ui"
	"go.uber.org/zap"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

const (
	redirectToToken = "forms_plugin_redirect_url"
)

func init() {
	caddy.RegisterModule(AuthProvider{})
}

// AuthProvider authorizes access to endpoints based on
// the presense and content of JWT token.
type AuthProvider struct {
	Name          string                   `json:"-"`
	AuthURLPath   string                   `json:"auth_url_path,omitempty"`
	UserInterface *UserInterfaceParameters `json:"ui,omitempty"`
	Backends      []*Backend               `json:"backends,omitempty"`
	Jwt           TokenParameters          `json:"jwt,omitempty"`
	logger        *zap.Logger              `json:"-"`
	uiFactory     *ui.UserInterfaceFactory `json:"-"`
}

// UserInterfaceParameters represent a common set of configuration settings
// for HTML UI.
type UserInterfaceParameters struct {
	Templates          map[string]string      `json:"templates,omitempty"`
	AllowRoleSelection bool                   `json:"allow_role_selection,omitempty"`
	Title              string                 `json:"title,omitempty"`
	LogoURL            string                 `json:"logo_url,omitempty"`
	LogoDescription    string                 `json:"logo_description,omitempty"`
	PrivateLinks       []ui.UserInterfaceLink `json:"private_links,omitempty"`
	AutoRedirectURL    string                 `json:"auto_redirect_url"`
}

// TokenParameters represent JWT parameters of CommonParameters.
type TokenParameters struct {
	TokenName     string `json:"token_name,omitempty"`
	TokenSecret   string `json:"token_secret,omitempty"`
	TokenIssuer   string `json:"token_issuer,omitempty"`
	TokenLifetime int    `json:"token_lifetime,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (AuthProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.forms",
		New: func() caddy.Module { return new(AuthProvider) },
	}
}

// Provision provisions JWT authorization provider
func (m *AuthProvider) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.logger.Info("provisioning plugin instance")
	m.Name = "forms"
	return nil
}

// Validate implements caddy.Validator.
func (m *AuthProvider) Validate() error {
	if m.AuthURLPath == "" {
		return fmt.Errorf("%s: auth_url_path must be set", m.Name)
	}

	m.logger.Info(
		"Authentication URL found",
		zap.String("auth_url_path", m.AuthURLPath),
	)

	m.logger.Info("validating plugin JWT settings")
	if m.Jwt.TokenName == "" {
		m.Jwt.TokenName = "access_token"
	}
	m.logger.Info(
		"found JWT token name",
		zap.String("jwt.token_name", m.Jwt.TokenName),
	)

	if m.Jwt.TokenSecret == "" {
		if os.Getenv("JWT_TOKEN_SECRET") == "" {
			return fmt.Errorf("%s: jwt_token_secret must be defined either "+
				"via JWT_TOKEN_SECRET environment variable or "+
				"via jwt.token_secret configuration element",
				m.Name,
			)
		}
		m.Jwt.TokenSecret = os.Getenv("JWT_TOKEN_SECRET")
	}

	if m.Jwt.TokenIssuer == "" {
		m.logger.Warn(
			"JWT token issuer not found, using default",
			zap.String("jwt.token_issuer", "localhost"),
		)
		m.Jwt.TokenIssuer = "localhost"
	}

	if m.Jwt.TokenLifetime == 0 {
		m.Jwt.TokenLifetime = 900
		m.logger.Info(
			"JWT token lifetime not found, using default",
			zap.Int("jwt.token_lifetime", m.Jwt.TokenLifetime),
		)
	} else {
		m.logger.Info(
			"JWT token lifetime found",
			zap.Int("jwt.token_lifetime", m.Jwt.TokenLifetime),
		)
	}

	// Backend Validation
	if len(m.Backends) == 0 {
		return fmt.Errorf("%s: no valid backend found", m.Name)
	}

	for _, backend := range m.Backends {
		if err := backend.Validate(); err != nil {
			return fmt.Errorf("%s: backend error: %s", m.Name, err)
		}
		if backend.Jwt.TokenName == "" {
			backend.Jwt.TokenName = m.Jwt.TokenName
		}
		if backend.Jwt.TokenSecret == "" {
			backend.Jwt.TokenSecret = m.Jwt.TokenSecret
		}
		if backend.Jwt.TokenIssuer == "" {
			backend.Jwt.TokenName = m.Jwt.TokenIssuer
		}
		if backend.Jwt.TokenLifetime == 0 {
			backend.Jwt.TokenLifetime = m.Jwt.TokenLifetime
		}

	}

	// UI Validation
	uiPages := map[string]string{
		"login": "default",
		//"portal": "default",
	}
	if m.UserInterface == nil {
		m.UserInterface = &UserInterfaceParameters{}
	}

	m.uiFactory = ui.NewUserInterfaceFactory()
	if m.UserInterface.Title == "" {
		m.uiFactory.Title = "Sign In"
	} else {
		m.uiFactory.Title = m.UserInterface.Title
	}
	if m.UserInterface.LogoURL != "" {
		m.uiFactory.LogoURL = m.UserInterface.LogoURL
		m.uiFactory.LogoDescription = m.UserInterface.LogoDescription
	}

	m.uiFactory.ActionEndpoint = m.AuthURLPath

	if len(m.UserInterface.PrivateLinks) > 0 {
		m.uiFactory.PrivateLinks = m.UserInterface.PrivateLinks
	}

	for tmplName, tmplAlias := range uiPages {
		useDefaultTemplate := false
		if m.UserInterface.Templates == nil {
			useDefaultTemplate = true
		} else {
			if _, exists := m.UserInterface.Templates[tmplName]; !exists {
				useDefaultTemplate = true
			}
		}

		if useDefaultTemplate {
			if err := m.uiFactory.AddBuiltinTemplate(tmplAlias); err != nil {
				return fmt.Errorf(
					"%s: UI settings validation error, failed loading built-in %s (%s) template: %s",
					m.Name, tmplName, tmplAlias, err,
				)
			}
			continue
		}

		if err := m.uiFactory.AddTemplate(tmplName, m.UserInterface.Templates[tmplName]); err != nil {
			return fmt.Errorf(
				"%s: UI settings validation error, failed loading template from %s: %s",
				m.Name, m.UserInterface.Templates[tmplName], err,
			)
		}
	}

	for tmplName := range m.UserInterface.Templates {
		if _, exists := uiPages[tmplName]; !exists {
			return fmt.Errorf(
				"%s: UI settings validation error, unsupported template type: %s",
				m.Name, tmplName,
			)
		}
	}

	return nil
}

func validateRequestCompliance(r *http.Request) (map[string]string, error) {
	var reqFields []string
	kv := make(map[string]string)
	var maxBytesLimit int64 = 1000
	var minBytesLimit int64 = 10
	if r.ContentLength > maxBytesLimit {
		return nil, fmt.Errorf("Request payload exceeded the limit of %d bytes: %d", maxBytesLimit, r.ContentLength)
	}
	if r.ContentLength < minBytesLimit {
		return nil, fmt.Errorf("Request payload is too small: %d", r.ContentLength)
	}
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/x-www-form-urlencoded" {
		return nil, fmt.Errorf("Request content type is not application/x-www-form-urlencoded")
	}

	rq := r.FormValue("activity")
	if rq == "" {
		rq = "login"
	}

	switch rq {
	case "login":
		reqFields = []string{"username", "password", "realm"}
	default:
		return nil, fmt.Errorf("request type is unsupported")
	}

	for _, k := range reqFields {
		if v := r.FormValue(k); v != "" {
			kv[k] = v
		}
	}

	if _, exists := kv["realm"]; !exists {
		kv["realm"] = "local"
	}

	return kv, nil
}

// Authenticate authorizes access based on the presense and content of JWT token.
func (m AuthProvider) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	var reqID string
	var userClaims *jwt.UserClaims
	var userAuthenticated bool
	if reqDump, err := httputil.DumpRequest(r, true); err == nil {
		m.logger.Debug(fmt.Sprintf("request: %s", reqDump))
	}

	uiArgs := m.uiFactory.GetArgs()

	// Generate request UUID
	reqID = uuid.New().String()

	m.logger.Debug(
		"Request received",
		zap.String("request_id", reqID),
		zap.String("method", r.Method),
		zap.String("http_proto", r.Proto),
		zap.String("remote_ip", r.RemoteAddr),
		zap.Int64("content_length", r.ContentLength),
		zap.String("host", r.Host),
	)

	// Handle query parameters
	if r.Method == "GET" {
		q := r.URL.Query()
		if _, exists := q["logout"]; exists {
			for _, k := range []string{redirectToToken, m.Jwt.TokenName} {
				w.Header().Add("Set-Cookie", k+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
			}
		} else {
			if redirectURL, exists := q["redirect_url"]; exists {
				w.Header().Set("Set-Cookie", redirectToToken+"="+redirectURL[0])
			}
		}
	}

	// Authentication Requests
	if r.Method == "POST" {
		authFound := false
		if kv, err := validateRequestCompliance(r); err == nil {
			for _, backend := range m.Backends {
				if backend.Realm == kv["realm"] {
					authFound = true
				} else {
					continue
				}
				userClaims, err = backend.Authenticate(reqID, kv)
				if err != nil {
					uiArgs.Message = "Authentication failed"
					w.WriteHeader(http.StatusUnauthorized)
					m.logger.Warn(
						"Authentication failed",
						zap.String("request_id", reqID),
						zap.String("error", err.Error()),
					)
				} else {
					userAuthenticated = true
					uiArgs.Authenticated = true
				}
			}
		} else {
			uiArgs.Message = "Authentication failed"
			m.logger.Warn(
				"Authentication failed",
				zap.String("request_id", reqID),
				zap.String("error", err.Error()),
			)
		}

		if !authFound {
			if uiArgs.Message == "" {
				uiArgs.Message = "Authentication failed"
				m.logger.Warn(
					"Authentication failed",
					zap.String("request_id", reqID),
					zap.String("error", "local backend not found"),
				)
			}
			w.WriteHeader(http.StatusBadRequest)
		}
	}

	// Render UI
	contentType := "text/html"
	content, uiErr := m.uiFactory.Render("login", uiArgs)
	if uiErr != nil {
		m.logger.Error(
			"Failed UI",
			zap.String("request_id", reqID),
			zap.String("error", uiErr.Error()),
		)
		w.WriteHeader(500)
		w.Write([]byte(`Internal Server Error`))
		return caddyauth.User{}, false, uiErr
	}

	// Wrap up
	if !userAuthenticated {
		w.Header().Set("Content-Type", contentType)
		w.Write(content.Bytes())
		return caddyauth.User{}, false, nil
	}

	userIdentity := caddyauth.User{
		ID: userClaims.Email,
		Metadata: map[string]string{
			"roles": strings.Join(userClaims.Roles, " "),
		},
	}

	if userClaims.Name != "" {
		userIdentity.Metadata["name"] = userClaims.Name
	}
	if userClaims.Email != "" {
		userIdentity.Metadata["email"] = userClaims.Email
	}

	m.logger.Debug(
		"Authentication succeeded",
		zap.String("request_id", reqID),
		zap.String("user_id", userIdentity.ID),
	)

	userToken, err := userClaims.GetToken("HS512", []byte(m.Jwt.TokenSecret))
	if err != nil {
		m.logger.Error(
			"Failed to get JWT token",
			zap.String("request_id", reqID),
			zap.String("user_id", userIdentity.ID),
			zap.String("error", err.Error()),
		)
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Authorization", "Bearer "+userToken)
	w.Header().Set("Set-Cookie", m.Jwt.TokenName+"="+userToken+" Secure; HttpOnly;")

	if cookie, err := r.Cookie(redirectToToken); err == nil {
		if redirectURL, err := url.Parse(cookie.Value); err == nil {
			m.logger.Debug(
				"Cookie-based redirect",
				zap.String("request_id", reqID),
				zap.String("user_id", userIdentity.ID),
				zap.String("redirect_url", redirectURL.String()),
			)
			w.Header().Set("Location", redirectURL.String())
			w.Header().Add("Set-Cookie", redirectToToken+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
			w.WriteHeader(303)
			return userIdentity, true, nil
		}
	}

	w.Header().Set("Content-Type", contentType)
	w.Write(content.Bytes())
	return userIdentity, true, nil
}

// Interface guards
var (
	_ caddy.Provisioner       = (*AuthProvider)(nil)
	_ caddy.Validator         = (*AuthProvider)(nil)
	_ caddyauth.Authenticator = (*AuthProvider)(nil)
)
