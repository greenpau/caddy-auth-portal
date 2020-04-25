package forms

import (
	"fmt"
	"github.com/greenpau/caddy-auth-jwt"
	"go.uber.org/zap"
	"time"
)

// Backend represents authentication provider.
type Backend struct {
	Type   string          `json:"type,omitempty"`
	Path   string          `json:"path,omitempty"`
	Realm  string          `json:"realm,omitempty"`
	Jwt    TokenParameters `json:"jwt,omitempty"`
	logger *zap.Logger
}

// Authenticate performs authentication.
func (b *Backend) Authenticate(reqID string, kv map[string]string) (*jwt.UserClaims, error) {
	if kv == nil {
		return nil, fmt.Errorf("No input to authenticate")
	}
	claims := &jwt.UserClaims{}
	claims.ExpiresAt = time.Now().Add(time.Duration(b.Jwt.TokenLifetime) * time.Second).Unix()
	claims.Name = "Greenberg, Paul"
	claims.Email = "greenpau@outlook.com"
	claims.Origin = "localhost"
	claims.Subject = "greenpau@outlook.com"
	claims.Roles = append(claims.Roles, "anonymous")
	return claims, nil
}

// Validate checks whether Backend is supported.
func (b *Backend) Validate() error {
	switch b.Type {
	case "boltdb":
		return nil
	default:
		return fmt.Errorf("backend type %s is unsupported", b.Type)
	}
	return nil
}
