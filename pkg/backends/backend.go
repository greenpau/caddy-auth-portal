// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package backends

import (
	"encoding/json"
	"fmt"

	jwtconfig "github.com/greenpau/caddy-auth-jwt/pkg/config"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/boltdb"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/ldap"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/local"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/oauth2"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/saml"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/x509"
	"github.com/greenpau/caddy-auth-portal/pkg/errors"
	"github.com/greenpau/go-identity"
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
	ConfigureTokenProvider(*jwtconfig.CommonTokenConfig) error
	ConfigureAuthenticator() error
	Validate() error
	Do(map[string]interface{}) error
	GetPublicKeys(map[string]interface{}) ([]*identity.PublicKey, error)
	GetMfaTokens(map[string]interface{}) ([]*identity.MfaToken, error)
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
func (b *Backend) Configure(opts map[string]interface{}) error {
	for _, v := range []string{"logger", "token_provider"} {
		if _, exists := opts[v]; !exists {
			return errors.ErrBackendConfigureOptionNotFound.WithArgs(v)
		}
		if opts[v] == nil {
			return errors.ErrBackendConfigureOptionNilValue.WithArgs(v)
		}
	}
	if err := b.driver.ConfigureLogger(opts["logger"].(*zap.Logger)); err != nil {
		return err
	}
	if err := b.driver.ConfigureTokenProvider(opts["token_provider"].(*jwtconfig.CommonTokenConfig)); err != nil {
		return err
	}
	if err := b.driver.ConfigureAuthenticator(); err != nil {
		return err
	}
	return nil
}

// Do performs the requested operation.
func (b *Backend) Do(opts map[string]interface{}) error {
	if len(opts) == 0 {
		return fmt.Errorf("no input found")
	}
	if _, exists := opts["name"]; !exists {
		return fmt.Errorf("no operation name found")
	}
	return b.driver.Do(opts)
}

// GetPublicKeys return a list of public keys associated with a user.
func (b *Backend) GetPublicKeys(opts map[string]interface{}) ([]*identity.PublicKey, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("no input found")
	}
	if _, exists := opts["key_usage"]; !exists {
		return nil, fmt.Errorf("no key usage found")
	}
	return b.driver.GetPublicKeys(opts)
}

// GetMfaTokens return a list of MFA tokens associated with a user.
func (b *Backend) GetMfaTokens(opts map[string]interface{}) ([]*identity.MfaToken, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("no input found")
	}
	return b.driver.GetMfaTokens(opts)
}

// Authenticate performs authentication with an authentication provider.
func (b *Backend) Authenticate(opts map[string]interface{}) (map[string]interface{}, error) {
	return b.driver.Authenticate(opts)
}

// Validate checks whether an authentication provider is functional.
func (b *Backend) Validate() error {
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
