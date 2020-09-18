package portal

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
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
	Name             string                      `json:"-"`
	Provisioned      bool                        `json:"-"`
	ProvisionFailed  bool                        `json:"-"`
	PrimaryInstance  bool                        `json:"primary,omitempty"`
	Context          string                      `json:"context,omitempty"`
	AuthURLPath      string                      `json:"auth_url_path,omitempty"`
	UserInterface    *UserInterfaceParameters    `json:"ui,omitempty"`
	UserRegistration *UserRegistrationParameters `json:"registration,omitempty"`
	Cookies          *cookies.Cookies            `json:"cookies,omitempty"`
	Backends         []Backend                   `json:"backends,omitempty"`
	TokenProvider    *jwt.TokenProviderConfig    `json:"jwt,omitempty"`
	TokenValidator   *jwt.TokenValidator         `json:"-"`
	logger           *zap.Logger
	uiFactory        *ui.UserInterfaceFactory
	startedAt        time.Time
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
	opts := make(map[string]interface{})
	opts["request_id"] = GetRequestID(r)
	opts["content_type"] = GetContentType(r)
	opts["authenticated"] = false
	opts["auth_backend_found"] = false
	opts["auth_credentials_found"] = false

	// Find JWT tokens, if any, and validate them.
	if claims, authOK, err := m.TokenValidator.Authorize(r, nil); authOK {
		opts["authenticated"] = true
		opts["user_claims"] = claims
	} else {
		if err != nil {
			switch err.Error() {
			case "[Token is expired]":
				return m.HandleSessionLoginRedirect(w, r, opts)
			case "no token found":
			default:
				m.logger.Debug("Authorization failed",
					zap.String("request_id", opts["request_id"].(string)),
					zap.Any("error", err.Error()),
				)
			}
		}
	}

	// Handle requests based on query parameters.
	if r.Method == "GET" {
		q := r.URL.Query()
		if redirectURL, exists := q["redirect_url"]; exists {
			w.Header().Set("Set-Cookie", redirectToToken+"="+redirectURL[0])
		}
	}

	// Perform request routing
	urlPath := strings.TrimPrefix(r.URL.Path, m.AuthURLPath)
	urlPath = strings.TrimLeft(urlPath, "/")
	switch {
	case strings.HasPrefix(urlPath, "register"):
		// TODO: registration should be unavailable for authenticated users
		opts["flow"] = "register"
		return m.HandleRegister(w, r, opts)
	case strings.HasPrefix(urlPath, "recover"),
		strings.HasPrefix(urlPath, "forgot"):
		// TODO: password recovery should be unavailable for authenticated users
		// opts["flow"] = "recover"
		opts["flow"] = "unsupported_feature"
		return m.HandleGeneric(w, r, opts)
	case strings.HasPrefix(urlPath, "logout"),
		strings.HasPrefix(urlPath, "logoff"):
		opts["flow"] = "logout"
		return m.HandleSessionLogoff(w, r, opts)
	case strings.HasPrefix(urlPath, "assets"):
		opts["flow"] = "assets"
		return m.HandleServeStaticAssets(w, r, opts)
	case strings.HasPrefix(urlPath, "whoami"):
		opts["flow"] = "whoami"
		return m.HandleWhoami(w, r, opts)
	case strings.HasPrefix(urlPath, "profile"):
		opts["flow"] = "profile"
		return m.HandleProfile(w, r, opts)
	case strings.HasPrefix(urlPath, "portal"):
		opts["flow"] = "portal"
		return m.HandlePortal(w, r, opts)
	case strings.HasPrefix(urlPath, "login"), urlPath == "":
		opts["flow"] = "login"
		return m.HandleLogin(w, r, opts)
	default:
		opts["flow"] = "not_found"
		return m.HandleGeneric(w, r, opts)
	}
}

// Interface guards
var (
	_ caddy.Provisioner           = (*AuthPortal)(nil)
	_ caddy.Validator             = (*AuthPortal)(nil)
	_ caddyhttp.MiddlewareHandler = (*AuthPortal)(nil)
)
