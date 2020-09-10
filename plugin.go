package portal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	jwt "github.com/greenpau/caddy-auth-jwt"
	ui "github.com/greenpau/caddy-auth-ui"
	uuid "github.com/satori/go.uuid"
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
	mu              sync.Mutex
	Name            string                   `json:"-"`
	Provisioned     bool                     `json:"-"`
	ProvisionFailed bool                     `json:"-"`
	PrimaryInstance bool                     `json:"primary,omitempty"`
	Context         string                   `json:"context,omitempty"`
	AuthURLPath     string                   `json:"auth_url_path,omitempty"`
	UserInterface   *UserInterfaceParameters `json:"ui,omitempty"`
	Backends        []Backend                `json:"backends,omitempty"`
	TokenProvider   *jwt.TokenProviderConfig `json:"jwt,omitempty"`
	TokenValidator  *jwt.TokenValidator      `json:"-"`
	logger          *zap.Logger
	uiFactory       *ui.UserInterfaceFactory
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

// Authenticate authorizes access based on the presense and content of JWT token.
func (m AuthPortal) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	var reqID string
	var userClaims *jwt.UserClaims
	var userAuthenticated bool
	var authStatusCode int
	var authBackendFound bool
	var credentialsFound bool

	uiArgs := m.uiFactory.GetArgs()

	// Generate request UUID
	reqID = uuid.NewV4().String()
	acceptHeaderStr := r.Header.Get("Accept")
	if acceptHeaderStr == "" {
		acceptHeaderStr = "any"
	}

	m.logger.Debug(
		"Request received",
		zap.String("request_id", reqID),
		zap.String("method", r.Method),
		zap.String("http_proto", r.Proto),
		zap.String("remote_ip", r.RemoteAddr),
		zap.Int64("content_length", r.ContentLength),
		zap.String("host", r.Host),
		zap.String("requested_response_types", acceptHeaderStr),
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
			return nil
		}
		if redirectURL, exists := q["redirect_url"]; exists {
			w.Header().Set("Set-Cookie", redirectToToken+"="+redirectURL[0])
		}
	}

	// Try to authorize with JWT tokens
	userClaims, userAuthenticated, err := m.TokenValidator.Authorize(r, nil)
	if userAuthenticated {
		uiArgs.Authenticated = true
	} else {
		if err != nil {
			m.logger.Debug(
				"Authorization failed",
				zap.String("request_id", reqID),
				zap.Any("error", err.Error()),
			)
			if err.Error() == "[Token is expired]" {
				for _, k := range []string{redirectToToken, m.TokenProvider.TokenName} {
					w.Header().Add("Set-Cookie", k+"=delete; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
				}
				w.Header().Set("Location", m.AuthURLPath)
				w.WriteHeader(303)
				return nil
			}
		}
	}

	// Authentication Requests
	if !userAuthenticated {
		if credentials, err := parseCredentials(r); err == nil {
			if credentials != nil {
				credentialsFound = true
				for _, backend := range m.Backends {
					if backend.GetRealm() != credentials["realm"] {
						continue
					}
					authBackendFound = true
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
						userAuthenticated = true
						uiArgs.Authenticated = true
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

		if credentialsFound && !authBackendFound {
			m.logger.Warn(
				"Authentication failed",
				zap.String("request_id", reqID),
				zap.String("error", "no matching auth backend found"),
			)
		}
	}

	// Render UI
	contentType := "text/html"
	if acceptHeaderStr == "application/json" {
		contentType = acceptHeaderStr
	}
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
		if credentialsFound && uiArgs.Message == "" {
			uiArgs.Message = "Authentication failed"
		}
		w.Header().Set("Content-Type", contentType)
		var contentBytes []byte
		if contentType == "application/json" {
			// respond with JSON
			authResponse := AuthResponse{}
			if credentialsFound {
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
