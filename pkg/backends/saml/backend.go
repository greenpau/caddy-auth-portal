package saml

import (
	"fmt"
	"sync"

	jwt "github.com/greenpau/caddy-auth-jwt"
	"go.uber.org/zap"
)

var (
	globalAuthenticator *Authenticator
)

func init() {
	globalAuthenticator = NewAuthenticator()
	return
}

// Backend represents authentication provider with SAML backend.
type Backend struct {
	Name          string                   `json:"name,omitempty"`
	Method        string                   `json:"method,omitempty"`
	Realm         string                   `json:"realm,omitempty"`
	TokenProvider *jwt.TokenProviderConfig `json:"-"`
	Authenticator *Authenticator           `json:"-"`
	logger        *zap.Logger
}

// NewDatabaseBackend return an instance of authentication provider
// with SAML backend.
func NewDatabaseBackend() *Backend {
	b := &Backend{
		Method:        "saml",
		TokenProvider: jwt.NewTokenProviderConfig(),
		Authenticator: globalAuthenticator,
	}
	return b
}

// Authenticator represents database connector.
type Authenticator struct {
	mux    sync.Mutex
	realm  string
	logger *zap.Logger
}

// NewAuthenticator returns an instance of Authenticator.
func NewAuthenticator() *Authenticator {
	return &Authenticator{}
}

// ConfigureRealm configures a domain name (realm) associated with
// the instance of authenticator.
func (sa *Authenticator) ConfigureRealm(realm string) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	if realm == "" {
		return fmt.Errorf("no realm found")
	}
	sa.realm = realm
	sa.logger.Info(
		"SAML plugin configuration",
		zap.String("phase", "realm"),
		zap.String("realm", realm),
	)
	return nil
}

// ConfigureAuthenticator configures backend for .
func (b *Backend) ConfigureAuthenticator() error {
	if b.Authenticator == nil {
		b.Authenticator = NewAuthenticator()
	}

	b.Authenticator.logger = b.logger

	if err := b.Authenticator.ConfigureRealm(b.Realm); err != nil {
		b.logger.Error("failed configuring realm (domain) for SAML authentication",
			zap.String("error", err.Error()))
		return err
	}

	return nil
}

// ValidateConfig checks whether Backend has mandatory configuration.
func (b *Backend) ValidateConfig() error {
	return nil
}

// Authenticate performs authentication.
func (b *Backend) Authenticate(reqID string, kv map[string]string) (*jwt.UserClaims, int, error) {
	return nil, 400, fmt.Errorf("unsupported backend %s", b.Name)
}

// Validate checks whether Backend is functional.
func (b *Backend) Validate() error {
	if err := b.ValidateConfig(); err != nil {
		return err
	}
	if b.logger == nil {
		return fmt.Errorf("SAML backend logger is nil")
	}

	b.logger.Info("validating SAML backend")

	if b.Authenticator == nil {
		return fmt.Errorf("SAML authenticator is nil")
	}

	b.logger.Info("successfully validated SAML backend")
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
