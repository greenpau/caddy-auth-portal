package forms

import (
	"fmt"
	"github.com/greenpau/caddy-auth-jwt"
	//"github.com/mattn/go-sqlite3"
	//"encoding/json"
	"go.uber.org/zap"
	"time"
)

// SqliteBackend represents authentication provider with SQLite backend.
type SqliteBackend struct {
	Realm         string                   `json:"realm,omitempty"`
	Path          string                   `json:"path,omitempty"`
	TokenProvider *jwt.TokenProviderConfig `json:"jwt,omitempty"`
	logger        *zap.Logger
}

// NewSqliteDatabaseBackend return an instance of authentication provider
// with SQLite backend.
func NewSqliteDatabaseBackend() *SqliteBackend {
	b := &SqliteBackend{
		TokenProvider: jwt.NewTokenProviderConfig(),
	}
	return b
}

// Authenticate performs authentication.
func (b *SqliteBackend) Authenticate(reqID string, kv map[string]string) (*jwt.UserClaims, error) {
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

// Validate checks whether SqliteBackend is functional.
func (b *SqliteBackend) Validate() error {
	if b.Realm == "" {
		b.Realm = "local"
	}
	return nil
}

// ValidateConfig checks whether SqliteBackend has mandatory configuration.
func (b *SqliteBackend) ValidateConfig() error {
	if b.Path == "" {
		return fmt.Errorf("path is empty")
	}
	return nil
}

// GetRealm return authentication realm.
func (b *SqliteBackend) GetRealm() string {
	return b.Realm
}

// ConfigureTokenProvider configures TokenProvider.
func (b *SqliteBackend) ConfigureTokenProvider(upstream *jwt.TokenProviderConfig) error {
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
