package portal

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/greenpau/caddy-auth-jwt"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/bolt"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/ldap"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/local"
	"go.uber.org/zap"
)

// Backend is an authentication backend.
type Backend struct {
	authMethod string
	driver     BackendDriver
}

// BackendDriver is an interface to an authentication provider.
type BackendDriver interface {
	GetRealm() string
	Authenticate(string, map[string]string) (*jwt.UserClaims, int, error)
	ConfigureLogger(*zap.Logger) error
	ConfigureTokenProvider(*jwt.TokenProviderConfig) error
	ConfigureAuthenticator() error
	Validate() error
}

// GetRealm returns realm associated with an authentication provider.
func (b *Backend) GetRealm() string {
	return b.driver.GetRealm()
}

// Configure configures backend with the authentication provider settings.
func (b *Backend) Configure(p *AuthPortal) error {
	if err := b.driver.ConfigureLogger(p.logger); err != nil {
		return err
	}
	if err := b.driver.ConfigureTokenProvider(p.TokenProvider); err != nil {
		return err
	}
	if err := b.driver.ConfigureAuthenticator(); err != nil {
		return err
	}

	return nil
}

// Authenticate performs authentication with an authentication provider.
func (b *Backend) Authenticate(reqID string, data map[string]string) (*jwt.UserClaims, int, error) {
	return b.driver.Authenticate(reqID, data)
}

// Validate checks whether an authentication provider is functional.
func (b *Backend) Validate(p *AuthPortal) error {
	return b.driver.Validate()
}

// MarshalJSON packs configuration info JSON byte array
func (b Backend) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.driver)
}

// UnmarshalJSON unpacks configuration into appropriate structures.
func (b *Backend) UnmarshalJSON(data []byte) error {
	if len(data) < 10 {
		return fmt.Errorf("invalid configuration: %s", data)
	}
	if bytes.Contains(data, []byte("\"method\":\"boltdb\"")) {
		b.authMethod = "boltdb"
		driver := bolt.NewDatabaseBackend()
		if err := json.Unmarshal(data, driver); err != nil {
			return fmt.Errorf("invalid boltdb configuration, error: %s, config: %s", err, data)
		}
		if err := driver.ValidateConfig(); err != nil {
			return fmt.Errorf("invalid boltdb configuration, error: %s, config: %s", err, data)
		}
		b.driver = driver
		return nil
	}

	if bytes.Contains(data, []byte("\"method\":\"ldap\"")) {
		b.authMethod = "ldap"
		driver, err := newLdapDriver(data)
		if err != nil {
			return err
		}
		b.driver = driver
		return nil
	}

	if bytes.Contains(data, []byte("\"method\":\"local\"")) {
		b.authMethod = "local"
		driver, err := newLocalDriver(data)
		if err != nil {
			return err
		}
		b.driver = driver
		return nil
	}

	return fmt.Errorf("unsupported authentication method configuration: %s", data)
}

// NewBackendFromBytes returns backend instance based on authentication method
// and JSON configuration data.
func NewBackendFromBytes(method string, data []byte) (*Backend, error) {
	switch method {
	case "ldap":
		return NewLdapBackendFromBytes(data)
	case "local":
		return NewLocalBackendFromBytes(data)
	default:
		return nil, fmt.Errorf("unsupported authentication method configuration: %s", data)
	}
}

// NewLdapBackendFromBytes returns LDAP backend.
func NewLdapBackendFromBytes(data []byte) (*Backend, error) {
	b := &Backend{}
	b.authMethod = "ldap"
	driver, err := newLdapDriver(data)
	if err != nil {
		return nil, err
	}
	b.driver = driver
	return b, nil
}

// NewLocalBackendFromBytes returns local backend.
func NewLocalBackendFromBytes(data []byte) (*Backend, error) {
	b := &Backend{}
	b.authMethod = "local"
	driver, err := newLocalDriver(data)
	if err != nil {
		return nil, err
	}
	b.driver = driver
	return b, nil
}

func newLdapDriver(data []byte) (*ldap.Backend, error) {
	driver := ldap.NewDatabaseBackend()
	if err := json.Unmarshal(data, driver); err != nil {
		return nil, fmt.Errorf("invalid LDAP configuration, error: %s, config: %s", err, data)
	}
	if err := driver.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid LDAP configuration, error: %s, config: %s", err, data)
	}
	return driver, nil
}

func newLocalDriver(data []byte) (*local.Backend, error) {
	driver := local.NewDatabaseBackend()
	if err := json.Unmarshal(data, driver); err != nil {
		return nil, fmt.Errorf("invalid local configuration, error: %s, config: %s", err, data)
	}
	if err := driver.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid local configuration, error: %s, config: %s", err, data)
	}
	return driver, nil
}
