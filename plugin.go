package forms

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"github.com/greenpau/caddy-auth-jwt"
	"github.com/greenpau/caddy-auth-ui"
	"github.com/satori/go.uuid"
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
	Name           string                   `json:"-"`
	AuthURLPath    string                   `json:"auth_url_path,omitempty"`
	UserInterface  *UserInterfaceParameters `json:"ui,omitempty"`
	Backends       []Backend                `json:"backends,omitempty"`
	TokenProvider  *jwt.TokenProviderConfig `json:"jwt,omitempty"`
	TokenValidator *jwt.TokenValidator      `json:"-"`
	logger         *zap.Logger              `json:"-"`
	uiFactory      *ui.UserInterfaceFactory `json:"-"`
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

	if m.TokenProvider.TokenName == "" {
		m.TokenProvider.TokenName = "access_token"
	}
	m.logger.Info(
		"JWT token name found",
		zap.String("token_name", m.TokenProvider.TokenName),
	)

	if m.TokenProvider.TokenSecret == "" {
		if os.Getenv("JWT_TOKEN_SECRET") == "" {
			return fmt.Errorf("%s: token_secret must be defined either "+
				"via JWT_TOKEN_SECRET environment variable or "+
				"via token_secret configuration element",
				m.Name,
			)
		}
		m.TokenProvider.TokenSecret = os.Getenv("JWT_TOKEN_SECRET")
	}

	if m.TokenProvider.TokenIssuer == "" {
		m.logger.Warn("JWT token issuer not found, using default")
		m.TokenProvider.TokenIssuer = "localhost"
	}

	if m.TokenProvider.TokenOrigin == "" {
		m.logger.Warn("JWT token origin not found, using default")
		m.TokenProvider.TokenOrigin = "localhost"
	}

	m.logger.Info(
		"JWT token origin found",
		zap.String("token_origin", m.TokenProvider.TokenOrigin),
	)

	m.logger.Info(
		"JWT token issuer found",
		zap.String("token_issuer", m.TokenProvider.TokenIssuer),
	)

	if m.TokenProvider.TokenLifetime == 0 {
		m.logger.Warn("JWT token lifetime not found, using default")
		m.TokenProvider.TokenLifetime = 900
	}
	m.logger.Info(
		"JWT token lifetime found",
		zap.Int("token_lifetime", m.TokenProvider.TokenLifetime),
	)

	// Backend Validation
	if len(m.Backends) == 0 {
		return fmt.Errorf("%s: no valid backend found", m.Name)
	}

	for _, backend := range m.Backends {
		if err := backend.Configure(m); err != nil {
			return fmt.Errorf("%s: backend configuration error: %s", m.Name, err)
		}
		if err := backend.Validate(m); err != nil {
			return fmt.Errorf("%s: backend validation error: %s", m.Name, err)
		}
	}

	// UI Validation
	uiPages := map[string]string{
		"login":  "forms_login",
		"portal": "forms_portal",
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
		m.logger.Debug(
			"configuring UI templates",
			zap.String("template_name", tmplName),
			zap.String("template_alias", tmplAlias),
		)
		useDefaultTemplate := false
		if m.UserInterface.Templates == nil {
			m.logger.Debug("UI templates were not defined, using default template")
			useDefaultTemplate = true
		} else {
			if v, exists := m.UserInterface.Templates[tmplName]; !exists {
				m.logger.Debug(
					"UI template was not defined, using default template",
					zap.String("template_name", tmplName),
				)
				useDefaultTemplate = true
			} else {
				m.logger.Debug(
					"UI template definition found",
					zap.String("template_name", tmplName),
					zap.String("template_path", v),
				)
			}
		}

		if useDefaultTemplate {
			m.logger.Debug(fmt.Sprintf("adding UI template %s to UI factory", tmplAlias))
			if err := m.uiFactory.AddBuiltinTemplate(tmplAlias); err != nil {
				return fmt.Errorf(
					"%s: UI settings validation error, failed loading built-in %s (%s) template: %s",
					m.Name, tmplName, tmplAlias, err,
				)
			}
			m.uiFactory.Templates[tmplName] = m.uiFactory.Templates[tmplAlias]
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

	m.TokenValidator = jwt.NewTokenValidator()
	m.TokenValidator.TokenSecret = m.TokenProvider.TokenSecret
	if err := m.TokenValidator.ConfigureTokenBackends(); err != nil {
		return fmt.Errorf(
			"%s: token validator backend configuration failed: %s",
			m.Name, err,
		)
	}
	entry := jwt.NewAccessListEntry()
	entry.Allow()
	if err := entry.SetClaim("roles"); err != nil {
		return fmt.Errorf(
			"%s: default access list configuration error: %s",
			m.Name, err,
		)
	}
	for _, v := range []string{"anonymous", "guest", "*"} {
		if err := entry.AddValue(v); err != nil {
			return fmt.Errorf(
				"%s: default access list configuration error: %s",
				m.Name, err,
			)
		}
	}
	m.TokenValidator.AccessList = append(m.TokenValidator.AccessList, entry)
	return nil
}

func validateRequestCompliance(r *http.Request) (map[string]string, error) {
	var reqFields []string
	kv := make(map[string]string)
	var maxBytesLimit int64 = 1000
	var minBytesLimit int64 = 15
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
	var authStatusCode int
	if reqDump, err := httputil.DumpRequest(r, true); err == nil {
		m.logger.Debug(fmt.Sprintf("request: %s", reqDump))
	}

	uiArgs := m.uiFactory.GetArgs()

	// Generate request UUID
	reqID = uuid.NewV4().String()

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
			for _, k := range []string{redirectToToken, m.TokenProvider.TokenName} {
				w.Header().Add("Set-Cookie", k+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
			}
			w.Header().Set("Location", m.AuthURLPath)
			w.WriteHeader(303)
			return caddyauth.User{}, false, nil
		}
		if redirectURL, exists := q["redirect_url"]; exists {
			w.Header().Set("Set-Cookie", redirectToToken+"="+redirectURL[0])
		}
	}

	// Try to authorize with JWT tokens
	userClaims, userAuthenticated, _ = m.TokenValidator.Authorize(r)
	if userAuthenticated {
		uiArgs.Authenticated = true
	}

	// Authentication Requests
	if r.Method == "POST" && !userAuthenticated {
		authFound := false
		if kv, err := validateRequestCompliance(r); err == nil {
			for _, backend := range m.Backends {
				if backend.GetRealm() != kv["realm"] {
					continue
				}
				authFound = true
				userClaims, authStatusCode, err = backend.Authenticate(reqID, kv)
				if err != nil {
					uiArgs.Message = "Authentication failed"
					w.WriteHeader(authStatusCode)
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
					zap.String("error", "no matching auth backend found"),
				)
			}
			w.WriteHeader(http.StatusBadRequest)
		}
	}

	// Render UI
	contentType := "text/html"
	if m.UserInterface.Title == "" {
		uiArgs.Title = "Sign In"
	} else {
		uiArgs.Title = m.UserInterface.Title
	}

	// Wrap up
	if !userAuthenticated {
		content, err := m.uiFactory.Render("login", uiArgs)
		if err != nil {
			m.logger.Error(
				"Failed UI",
				zap.String("request_id", reqID),
				zap.String("error", err.Error()),
			)
			w.WriteHeader(500)
			w.Write([]byte(`Internal Server Error`))
			return caddyauth.User{}, false, err
		}
		w.Header().Set("Content-Type", contentType)
		w.Write(content.Bytes())
		return caddyauth.User{}, false, nil
	}

	if m.UserInterface.Title == "" {
		uiArgs.Title = "Welcome"
	}

	content, err := m.uiFactory.Render("portal", uiArgs)
	if err != nil {
		m.logger.Error(
			"Failed UI",
			zap.String("request_id", reqID),
			zap.String("error", err.Error()),
		)
		w.WriteHeader(500)
		w.Write([]byte(`Internal Server Error`))
		return caddyauth.User{}, false, err
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

	userToken, err := userClaims.GetToken("HS512", []byte(m.TokenProvider.TokenSecret))
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
	w.Header().Set("Set-Cookie", m.TokenProvider.TokenName+"="+userToken+" Secure; HttpOnly;")

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

	if r.Method == "POST" {
		w.Header().Set("Location", m.AuthURLPath)
		w.WriteHeader(303)
		return userIdentity, true, nil
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
