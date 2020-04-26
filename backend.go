package forms

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/greenpau/caddy-auth-jwt"
)

// Backend is an authentication backend.
type Backend struct {
	Driver BackendDriver
}

// BackendDriver is an interface to an authentication provider.
type BackendDriver interface {
	GetRealm() string
	Authenticate(string, map[string]string) (*jwt.UserClaims, error)
	ConfigureTokenProvider(*jwt.TokenProviderConfig) error
	Validate() error
}

// UnmarshalJSON unpacks configuration into appropriate structures.
func (b *Backend) UnmarshalJSON(data []byte) error {
	if len(data) < 10 {
		return fmt.Errorf("invalid configuration: %s", data)
	}
	if bytes.Contains(data, []byte("\"type\":\"boltdb\"")) {
		driver := NewBoltDatabaseBackend()
		if err := json.Unmarshal(data, driver); err != nil {
			return fmt.Errorf("invalid boltdb configuration, error: %s, config: %s", err, data)
		}
		if err := driver.ValidateConfig(); err != nil {
			return fmt.Errorf("invalid boltdb configuration, error: %s, config: %s", err, data)
		}
		b.Driver = driver
		return nil
	}

	if bytes.Contains(data, []byte("\"type\":\"sqlite3\"")) ||
		bytes.Contains(data, []byte("\"type\":\"sqlite\"")) {
		driver := NewSqliteDatabaseBackend()
		if err := json.Unmarshal(data, driver); err != nil {
			return fmt.Errorf("invalid SQLite configuration, error: %s, config: %s", err, data)
		}
		if err := driver.ValidateConfig(); err != nil {
			return fmt.Errorf("invalid SQLite configuration, error: %s, config: %s", err, data)
		}
		b.Driver = driver
		return nil
	}

	return fmt.Errorf("invalid configuration: %s", data)
}
