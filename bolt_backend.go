package forms

import (
	//"encoding/json"
	"fmt"
	"github.com/greenpau/caddy-auth-jwt"
	"go.uber.org/zap"
	"time"
)

// BoltBackend represents authentication provider with BoltDB backend.
type BoltBackend struct {
	Realm         string                   `json:"realm,omitempty"`
	Path          string                   `json:"path,omitempty"`
	TokenProvider *jwt.TokenProviderConfig `json:"jwt,omitempty"`
	logger        *zap.Logger
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
func (b *BoltBackend) Authenticate(reqID string, kv map[string]string) (*jwt.UserClaims, error) {
	if kv == nil {
		return nil, fmt.Errorf("No input to authenticate")
	}
	if _, exists := kv["username"]; !exists {
		return nil, fmt.Errorf("No username found")
	}
	if _, exists := kv["password"]; !exists {
		return nil, fmt.Errorf("No password found")
	}

	claims := &jwt.UserClaims{}
	claims.ExpiresAt = time.Now().Add(time.Duration(b.TokenProvider.TokenLifetime) * time.Second).Unix()
	claims.Name = "Greenberg, Paul"
	claims.Email = "greenpau@outlook.com"
	claims.Origin = "localhost"
	claims.Subject = kv["username"]
	//claims.Subject = "greenpau@outlook.com"
	claims.Roles = append(claims.Roles, "anonymous")
	return claims, nil
}

// Validate checks whether BoltBackend is functional.
func (b *BoltBackend) Validate() error {
	if b.Realm == "" {
		b.Realm = "local"
	}
	return nil
}

// ValidateConfig checks whether BoltBackend has mandatory configuration.
func (b *BoltBackend) ValidateConfig() error {
	if b.Path == "" {
		return fmt.Errorf("path is empty")
	}
	return nil
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
	if b.TokenProvider.TokenLifetime == 0 {
		b.TokenProvider.TokenLifetime = upstream.TokenLifetime
	}
	return nil
}
