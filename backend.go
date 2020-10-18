package portal

import (
	"encoding/json"
	"fmt"

	"github.com/greenpau/caddy-auth-jwt"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/boltdb"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/ldap"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/local"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/oauth2"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/saml"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/x509"
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
	GetName() string
	GetMethod() string
	Authenticate(map[string]interface{}) (map[string]interface{}, error)
	ConfigureLogger(*zap.Logger) error
	ConfigureTokenProvider(*jwt.CommonTokenConfig) error
	ConfigureAuthenticator() error
	Validate() error
}

// GetRealm returns realm associated with an authentication provider.
func (b *Backend) GetRealm() string {
	return b.driver.GetRealm()
}

// GetName returns the name associated with an authentication provider.
func (b *Backend) GetName() string {
	return b.driver.GetName()
}

// GetMethod returns the authentication method associated with an authentication provider.
func (b *Backend) GetMethod() string {
	return b.driver.GetMethod()
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
func (b *Backend) Authenticate(opts map[string]interface{}) (map[string]interface{}, error) {
	return b.driver.Authenticate(opts)
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
	var confData map[string]interface{}
	if len(data) < 10 {
		return fmt.Errorf("invalid configuration: %s", data)
	}

	if err := json.Unmarshal(data, &confData); err != nil {
		return fmt.Errorf("failed to unpack configuration data: %s", data)
	}

	if v, exists := confData["method"]; exists {
		switch vt := v.(type) {
		case string:
			b.authMethod = v.(string)
		default:
			return fmt.Errorf("failed to unpack configuration data, method key is not string but %v: %s", vt, data)
		}
	} else {
		return fmt.Errorf("failed to unpack configuration data, method key is missing: %s", data)
	}

	switch b.authMethod {
	case "boltdb":
		b.authMethod = "boltdb"
		driver := boltdb.NewDatabaseBackend()
		if err := json.Unmarshal(data, driver); err != nil {
			return fmt.Errorf("invalid boltdb configuration, error: %s, config: %s", err, data)
		}
		if err := driver.ValidateConfig(); err != nil {
			return fmt.Errorf("invalid boltdb configuration, error: %s, config: %s", err, data)
		}
		b.driver = driver
	case "ldap":
		driver, err := newLdapDriver(data)
		if err != nil {
			return err
		}
		b.driver = driver
	case "local":
		b.authMethod = "local"
		driver, err := newLocalDriver(data)
		if err != nil {
			return err
		}
		b.driver = driver
	case "saml":
		b.authMethod = "saml"
		driver, err := newSamlDriver(data)
		if err != nil {
			return err
		}
		b.driver = driver

	case "x509":
		b.authMethod = "x509"
		driver, err := newX509Driver(data)
		if err != nil {
			return err
		}
		b.driver = driver

	case "oauth2":
		b.authMethod = "oauth2"
		driver, err := newOauth2Driver(data)
		if err != nil {
			return err
		}
		b.driver = driver
	default:
		return fmt.Errorf("unsupported authentication method configuration: %s", data)
	}
	return nil
}

// NewBackendFromBytes returns backend instance based on authentication method
// and JSON configuration data.
func NewBackendFromBytes(name, method string, data []byte) (*Backend, error) {
	switch method {
	case "ldap":
		return NewLdapBackendFromBytes(name, data)
	case "local":
		return NewLocalBackendFromBytes(name, data)
	default:
		return nil, fmt.Errorf("unsupported authentication method %s for %s configuration: %s", method, name, data)
	}
}

// NewLdapBackendFromBytes returns LDAP backend.
func NewLdapBackendFromBytes(name string, data []byte) (*Backend, error) {
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
func NewLocalBackendFromBytes(name string, data []byte) (*Backend, error) {
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

func newSamlDriver(data []byte) (*saml.Backend, error) {
	driver := saml.NewDatabaseBackend()
	if err := json.Unmarshal(data, driver); err != nil {
		return nil, fmt.Errorf("invalid SAML configuration, error: %s, config: %s", err, data)
	}
	if err := driver.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid SAML configuration, error: %s, config: %s", err, data)
	}
	return driver, nil
}

func newX509Driver(data []byte) (*x509.Backend, error) {
	driver := x509.NewDatabaseBackend()
	if err := json.Unmarshal(data, driver); err != nil {
		return nil, fmt.Errorf("invalid X.509 configuration, error: %s, config: %s", err, data)
	}
	if err := driver.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid X.509 configuration, error: %s, config: %s", err, data)
	}
	return driver, nil
}

func newOauth2Driver(data []byte) (*oauth2.Backend, error) {
	driver := oauth2.NewDatabaseBackend()
	if err := json.Unmarshal(data, driver); err != nil {
		return nil, fmt.Errorf("invalid OAuth2 configuration, error: %s, config: %s", err, data)
	}
	if err := driver.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid OAuth2 configuration, error: %s, config: %s", err, data)
	}
	return driver, nil
}
