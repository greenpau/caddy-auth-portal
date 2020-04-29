package forms

import (
	//"encoding/json"
	"fmt"
	"github.com/greenpau/caddy-auth-jwt"
	"go.uber.org/zap"
	//"time"
)

// BoltBackend represents authentication provider with BoltDB backend.
type BoltBackend struct {
	Realm         string                   `json:"realm,omitempty"`
	Path          string                   `json:"path,omitempty"`
	TokenProvider *jwt.TokenProviderConfig `json:"jwt,omitempty"`
	logger        *zap.Logger
}

// Configure configures backend with the authentication provider settings.
func (b *BoltBackend) Configure(p *AuthProvider) error {
	if p.logger == nil {
		return fmt.Errorf("upstream logger is nil")
	}
	b.logger = p.logger
	if err := b.ConfigureTokenProvider(p.TokenProvider); err != nil {
		return err
	}
	return nil
}

// NewBoltDatabaseBackend return an instance of authentication provider
// with BoltDB backend.
func NewBoltDatabaseBackend() *BoltBackend {
	b := &BoltBackend{
		TokenProvider: jwt.NewTokenProviderConfig(),
	}
	return b
}

// Authenticate performs authentication.
func (b *BoltBackend) Authenticate(reqID string, kv map[string]string) (*jwt.UserClaims, int, error) {
	if kv == nil {
		return nil, 400, fmt.Errorf("No input to authenticate")
	}
	if _, exists := kv["username"]; !exists {
		return nil, 400, fmt.Errorf("No username found")
	}
	if _, exists := kv["password"]; !exists {
		return nil, 400, fmt.Errorf("No password found")
	}

	return nil, 500, fmt.Errorf("BoltDB backend is under development")
}

// ValidateConfig checks whether SqliteBackend has mandatory configuration.
func (b *BoltBackend) ValidateConfig() error {
	if b.Path == "" {
		return fmt.Errorf("path is empty")
	}
	return nil
}

// Validate checks whether BoltBackend is functional.
func (b *BoltBackend) Validate(p *AuthProvider) error {
	if err := b.ValidateConfig(); err != nil {
		return err
	}
	return fmt.Errorf("BoltDB backend is under development")
}

// GetRealm return authentication realm.
func (b *BoltBackend) GetRealm() string {
	return b.Realm
}

// ConfigureTokenProvider configures TokenProvider.
func (b *BoltBackend) ConfigureTokenProvider(upstream *jwt.TokenProviderConfig) error {
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
