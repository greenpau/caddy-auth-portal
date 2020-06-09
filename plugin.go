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
	"strings"
	"sync"
)

const (
	redirectToToken = "FORMS_AUTH_PLUGIN_REDIRECT_URL"
)

// ProviderPool is the global authentication provider pool.
// It provides access to all instances of Forms plugin.
var ProviderPool *AuthProviderPool

func init() {
	ProviderPool = &AuthProviderPool{}
	caddy.RegisterModule(AuthProvider{})
}

// AuthProvider authorizes access to endpoints based on
// the credentials provided in a request.
type AuthProvider struct {
	mu              sync.Mutex
	Name            string                   `json:"-"`
	Provisioned     bool                     `json:"-"`
	ProvisionFailed bool                     `json:"-"`
	Master          bool                     `json:"master,omitempty"`
	Context         string                   `json:"context,omitempty"`
	AuthURLPath     string                   `json:"auth_url_path,omitempty"`
	UserInterface   *UserInterfaceParameters `json:"ui,omitempty"`
	Backends        []Backend                `json:"backends,omitempty"`
	TokenProvider   *jwt.TokenProviderConfig `json:"jwt,omitempty"`
	TokenValidator  *jwt.TokenValidator      `json:"-"`
	logger          *zap.Logger              `json:"-"`
	uiFactory       *ui.UserInterfaceFactory `json:"-"`
}

// CaddyModule returns the Caddy module information.
func (AuthProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.forms",
		New: func() caddy.Module { return new(AuthProvider) },
	}
}

// Provision provisions forms authentication provider
func (m *AuthProvider) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	ProviderPool.Register(m)
	m.logger.Info(
		"provisioned plugin instance",
		zap.String("instance_name", m.Name),
	)

	if !m.Master {
		if err := ProviderPool.Provision(m.Name); err != nil {
			return fmt.Errorf(
				"authentication provider provisioning error, instance %s, error: %s",
				m.Name, err,
			)
		}
	}
	return nil
}

// Validate implements caddy.Validator.
func (m *AuthProvider) Validate() error {
	m.logger.Info(
		"validated plugin instance",
		zap.String("instance_name", m.Name),
	)
	return nil
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
		if kv, err := parseRequest(r); err == nil {
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
		for _, k := range []string{m.TokenProvider.TokenName} {
			w.Header().Add("Set-Cookie", k+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
		}
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
