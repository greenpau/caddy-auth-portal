package forms

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/greenpau/caddy-auth-jwt"
)

// Backend is an authentication backend.
type Backend struct {
	bt     string
	driver BackendDriver
}

// BackendDriver is an interface to an authentication provider.
type BackendDriver interface {
	GetRealm() string
	Authenticate(string, map[string]string) (*jwt.UserClaims, int, error)
	Configure(*AuthProvider) error
	Validate(*AuthProvider) error
}

// GetRealm returns realm associated with an authentication provider.
func (b *Backend) GetRealm() string {
	return b.driver.GetRealm()
}

// Configure configures backend with the authentication provider settings.
func (b *Backend) Configure(p *AuthProvider) error {
	return b.driver.Configure(p)
}

// Authenticate performs authentication with an authentication provider.
func (b *Backend) Authenticate(reqID string, data map[string]string) (*jwt.UserClaims, int, error) {
	return b.driver.Authenticate(reqID, data)
}

// Validate checks whether an authentication provider is functional.
func (b *Backend) Validate(p *AuthProvider) error {
	return b.driver.Validate(p)
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
	if bytes.Contains(data, []byte("\"type\":\"boltdb\"")) {
		b.bt = "boltdb"
		driver := NewBoltDatabaseBackend()
		if err := json.Unmarshal(data, driver); err != nil {
			return fmt.Errorf("invalid boltdb configuration, error: %s, config: %s", err, data)
		}
		if err := driver.ValidateConfig(); err != nil {
			return fmt.Errorf("invalid boltdb configuration, error: %s, config: %s", err, data)
		}
		b.driver = driver
		return nil
	}

	if bytes.Contains(data, []byte("\"type\":\"sqlite3\"")) ||
		bytes.Contains(data, []byte("\"type\":\"sqlite\"")) {
		b.bt = "sqlite"
		driver := NewSqliteDatabaseBackend()
		if err := json.Unmarshal(data, driver); err != nil {
			return fmt.Errorf("invalid SQLite configuration, error: %s, config: %s", err, data)
		}
		if err := driver.ValidateConfig(); err != nil {
			return fmt.Errorf("invalid SQLite configuration, error: %s, config: %s", err, data)
		}
		b.driver = driver
		return nil
	}

	return fmt.Errorf("invalid configuration: %s", data)
}
