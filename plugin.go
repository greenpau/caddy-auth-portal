package portal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	jwt "github.com/greenpau/caddy-auth-jwt"
	"github.com/greenpau/caddy-auth-portal/pkg/cookies"
	ui "github.com/greenpau/caddy-auth-ui"
	"go.uber.org/zap"
)

const (
	redirectToToken = "AUTH_PORTAL_REDIRECT_URL"
)

// PortalPool is the global authentication provider pool.
// It provides access to all instances of authentication portal plugin.
var PortalPool *AuthPortalPool

func init() {
	PortalPool = &AuthPortalPool{}
	caddy.RegisterModule(AuthPortal{})
}

// AuthPortal authorizes access to endpoints based on
// the credentials provided in a request.
type AuthPortal struct {
	Name            string                   `json:"-"`
	Provisioned     bool                     `json:"-"`
	ProvisionFailed bool                     `json:"-"`
	PrimaryInstance bool                     `json:"primary,omitempty"`
	Context         string                   `json:"context,omitempty"`
	AuthURLPath     string                   `json:"auth_url_path,omitempty"`
	UserInterface   *UserInterfaceParameters `json:"ui,omitempty"`
	Cookies         *cookies.Cookies         `json:"cookies,omitempty"`
	Backends        []Backend                `json:"backends,omitempty"`
	TokenProvider   *jwt.TokenProviderConfig `json:"jwt,omitempty"`
	TokenValidator  *jwt.TokenValidator      `json:"-"`
	logger          *zap.Logger
	uiFactory       *ui.UserInterfaceFactory
	startedAt       time.Time
}

// CaddyModule returns the Caddy module information.
func (AuthPortal) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.auth_portal",
		New: func() caddy.Module { return new(AuthPortal) },
	}
}

// Provision provisions authentication portal provider
func (m *AuthPortal) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.startedAt = time.Now().UTC()
	if err := PortalPool.Register(m); err != nil {
		return fmt.Errorf(
			"authentication provider registration error, instance %s, error: %s",
			m.Name, err,
		)
	}
	if !m.PrimaryInstance {
		if err := PortalPool.Provision(m.Name); err != nil {
			return fmt.Errorf(
				"authentication provider provisioning error, instance %s, error: %s",
				m.Name, err,
			)
		}
	}
	m.logger.Info(
		"provisioned plugin instance",
		zap.String("instance_name", m.Name),
		zap.Time("started_at", m.startedAt),
	)
	return nil
}

// Validate implements caddy.Validator.
func (m *AuthPortal) Validate() error {
	m.logger.Info(
		"validated plugin instance",
		zap.String("instance_name", m.Name),
	)
	return nil
}

// ServeHTTP authorizes access based on the presense and content of JWT token.
func (m AuthPortal) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	var userClaims *jwt.UserClaims

	opts := make(map[string]interface{})
	uiArgs := m.uiFactory.GetArgs()
	opts["request_id"] = GetRequestID(r)
	opts["content_type"] = GetContentType(r)
	opts["authenticated"] = false
	opts["auth_backend_found"] = false
	opts["auth_credentials_found"] = false
	reqID := opts["request_id"].(string)

	// Handle requests based on query parameters.
	if r.Method == "GET" {
		q := r.URL.Query()
		if _, exists := q["logout"]; exists {
			return m.DoSessionLogoff(w, r, opts)
		}
		if _, exists := q["register"]; exists {
			return m.DoRedirectUnsupported(w, r, opts)
		}
		if _, exists := q["forgot"]; exists {
			return m.DoRedirectUnsupported(w, r, opts)
		}
		if redirectURL, exists := q["redirect_url"]; exists {
			w.Header().Set("Set-Cookie", redirectToToken+"="+redirectURL[0])
		}
	}

	// Find JWT tokens, if any, and validate them.
	if claims, authOK, err := m.TokenValidator.Authorize(r, nil); authOK {
		uiArgs.Authenticated = true
		opts["authenticated"] = true
		userClaims = claims
	} else {
		if err != nil {
			switch err.Error() {
			case "[Token is expired]":
				return m.DoSessionLoginRedirect(w, r, opts)
			case "no token found":
			default:
				m.logger.Debug("Authorization failed", zap.String("request_id", reqID), zap.Any("error", err.Error()))
			}
		}
	}

	// Authentication Requests
	if !opts["authenticated"].(bool) {
		if credentials, err := parseCredentials(r); err == nil {
			if credentials != nil {
				opts["auth_credentials_found"] = true
				for _, backend := range m.Backends {
					if backend.GetRealm() != credentials["realm"] {
						continue
					}
					opts["auth_backend_found"] = true
					var authStatusCode int
					userClaims, authStatusCode, err = backend.Authenticate(reqID, credentials)
					if err != nil {
						uiArgs.Message = "Authentication failed"
						w.WriteHeader(authStatusCode)
						m.logger.Warn(
							"Authentication failed",
							zap.String("request_id", reqID),
							zap.String("error", err.Error()),
						)
					} else {
						opts["authenticated"] = true
						uiArgs.Authenticated = true
						m.logger.Debug(
							"Authentication succeeded",
							zap.String("request_id", reqID),
							zap.Any("user", userClaims),
						)
					}
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

		if opts["auth_credentials_found"].(bool) && !opts["auth_backend_found"].(bool) {
			m.logger.Warn(
				"Authentication failed",
				zap.String("request_id", reqID),
				zap.String("error", "no matching auth backend found"),
			)
		}
	}

	// Render UI
	contentType := "text/html"
	if opts["content_type"].(string) == "application/json" {
		contentType = opts["content_type"].(string)
	}

	if m.UserInterface.Title == "" {
		uiArgs.Title = "Sign In"
	} else {
		uiArgs.Title = m.UserInterface.Title
	}

	// Wrap up
	if !opts["authenticated"].(bool) {
		for _, k := range []string{m.TokenProvider.TokenName} {
			w.Header().Add("Set-Cookie", k+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
		}
		if opts["auth_credentials_found"].(bool) && uiArgs.Message == "" {
			uiArgs.Message = "Authentication failed"
		}
		w.Header().Set("Content-Type", contentType)
		var contentBytes []byte
		if contentType == "application/json" {
			// respond with JSON
			authResponse := AuthResponse{}
			if opts["auth_credentials_found"].(bool) {
				authResponse.Error = true
				authResponse.Message = uiArgs.Message
			} else {
				authResponse.Message = "authentication credentials required"
			}
			content, err := json.Marshal(authResponse)
			if err != nil {
				m.logger.Error(
					"Failed JSON response rendering",
					zap.String("request_id", reqID),
					zap.String("error", err.Error()),
				)
				w.WriteHeader(500)
				w.Write([]byte(`Internal Server Error`))
				return err
			}
			contentBytes = content
		} else {
			// respond with HTML UI
			content, err := m.uiFactory.Render("login", uiArgs)
			if err != nil {
				m.logger.Error(
					"Failed UI response rendering",
					zap.String("request_id", reqID),
					zap.String("error", err.Error()),
				)
				w.WriteHeader(500)
				w.Write([]byte(`Internal Server Error`))
				return err
			}
			contentBytes = content.Bytes()
		}

		w.WriteHeader(401)
		w.Write(contentBytes)
		return nil
	}

	if m.UserInterface.Title == "" {
		uiArgs.Title = "Welcome"
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
	w.Header().Set("Set-Cookie", m.TokenProvider.TokenName+"="+userToken+";"+m.Cookies.GetAttributes())

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
			return nil
		}
	}

	if r.Method == "POST" {
		w.Header().Set("Location", m.AuthURLPath)
		w.WriteHeader(303)
		return nil
	}

	w.Header().Set("Content-Type", contentType)
	if contentType == "application/json" {
		// respond with JSON
		authResponse := AuthResponse{
			Token: userToken,
		}
		content, err := json.Marshal(authResponse)
		if err != nil {
			m.logger.Error(
				"Failed JSON response rendering",
				zap.String("request_id", reqID),
				zap.String("error", err.Error()),
			)
			w.WriteHeader(500)
			w.Write([]byte(`Internal Server Error`))
			return err
		}
		w.Write(content)
	} else {
		// respond with HTML UI
		content, err := m.uiFactory.Render("portal", uiArgs)
		if err != nil {
			m.logger.Error(
				"Failed UI",
				zap.String("request_id", reqID),
				zap.String("error", err.Error()),
			)
			w.WriteHeader(500)
			w.Write([]byte(`Internal Server Error`))
			return err
		}
		w.Write(content.Bytes())
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*AuthPortal)(nil)
	_ caddy.Validator             = (*AuthPortal)(nil)
	_ caddyhttp.MiddlewareHandler = (*AuthPortal)(nil)
)
