package jwt

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"go.uber.org/zap"
	"net/http"
	"os"
)

func init() {
	caddy.RegisterModule(LocalAuthProvider{})
}

// LocalAuthProvider authorizes access to endpoints based on
// the presense and content of JWT token.
type LocalAuthProvider struct {
	Name        string      `json:"-"`
	AuthURLPath string      `json:"auth_url_path,omitempty"`
	logger      *zap.Logger `json:"-"`
}

// CaddyModule returns the Caddy module information.
func (LocalAuthProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.local",
		New: func() caddy.Module { return new(LocalAuthProvider) },
	}
}

// Provision provisions JWT authorization provider
func (m *LocalAuthProvider) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.logger.Info("provisioning plugin instance")
	m.Name = "local"
	return nil
}

// Validate implements caddy.Validator.
func (m *LocalAuthProvider) Validate() error {
	if m.TokenName == "" {
		m.TokenName = "access_token"
	}
	m.logger.Info(
		"found JWT token name",
		zap.String("token_name", m.TokenName),
	)

	if m.TokenSecret == "" {
		if os.Getenv("JWT_TOKEN_SECRET") == "" {
			return fmt.Errorf("%s: token_secret must be defined either "+
				"via JWT_TOKEN_SECRET environment variable or "+
				"via token_secret configuration element",
				m.Name,
			)
		}
	}

	if m.TokenIssuer == "" {
		m.logger.Warn(
			"JWT token issuer not found, using default",
			zap.String("token_issuer", "localhost"),
		)
		m.TokenIssuer = "localhost"
	}

	return nil
}

// Authenticate authorizes access based on the presense and content of JWT token.
func (m LocalAuthProvider) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	m.logger.Error(fmt.Sprintf("authenticating ... %v", r))
	w.Header().Set("WWW-Authenticate", "Bearer")
	return caddyauth.User{}, false, err
}

// Interface guards
var (
	_ caddy.Provisioner       = (*LocalAuthProvider)(nil)
	_ caddy.Validator         = (*LocalAuthProvider)(nil)
	_ caddyauth.Authenticator = (*LocalAuthProvider)(nil)
)
