package portal

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/greenpau/caddy-auth-portal/pkg/core"
	"github.com/satori/go.uuid"
)

func init() {
	caddy.RegisterModule(AuthMiddleware{})
}

// AuthMiddleware implements Form-Based, Basic, Local, LDAP,
// OpenID Connect, OAuth 2.0, SAML Authentication.
type AuthMiddleware struct {
	Portal *core.AuthPortal `json:"portal,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (AuthMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.auth_portal",
		New: func() caddy.Module { return new(AuthMiddleware) },
	}
}

// Provision provisions authentication portal provider
func (m *AuthMiddleware) Provision(ctx caddy.Context) error {
	opts := make(map[string]interface{})
	opts["logger"] = ctx.Logger(m)
	return m.Portal.Configure(opts)
}

// Validate implements caddy.Validator.
func (m *AuthMiddleware) Validate() error {
	return nil
}

// ServeHTTP authorizes access based on the presense and content of JWT token.
func (m AuthMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	reqID := GetRequestID(r)
	opts := make(map[string]interface{})
	opts["request_id"] = reqID
	return m.Portal.ServeHTTP(w, r, opts)
}

// GetRequestID returns request ID.
func GetRequestID(r *http.Request) string {
	rawRequestID := caddyhttp.GetVar(r.Context(), "request_id")
	if rawRequestID == nil {
		requestID := uuid.NewV4().String()
		caddyhttp.SetVar(r.Context(), "request_id", requestID)
		return requestID
	}
	return rawRequestID.(string)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*AuthMiddleware)(nil)
	_ caddy.Validator             = (*AuthMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*AuthMiddleware)(nil)
)
