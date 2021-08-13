// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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

	"github.com/greenpau/caddy-auth-portal/pkg/backends/ldap"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/local"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/oauth2"
	"github.com/greenpau/caddy-auth-portal/pkg/backends/saml"
	"github.com/greenpau/caddy-auth-portal/pkg/enums/operator"
	"github.com/greenpau/caddy-auth-portal/pkg/errors"
	"github.com/greenpau/go-identity/pkg/requests"
	"go.uber.org/zap"
)

// AuthMethodType identifies authentication provider type.
type AuthMethodType int

const (
	// Unknown is unknown provider type..
	Unknown AuthMethodType = iota
	// Local provides authentication with local database.
	Local
	// Ldap provides authentication with LDAP database.
	Ldap
	// Saml provides authentication with SAML.
	Saml
	// OAuth2 provides authentication with OAuth2.0/OpenID.
	OAuth2
)

// Config holds configuration for one of the supported authentication backends.
type Config struct {
	Local      *local.Config  `json:"local,omitempty" xml:"local" yaml:"local,omitempty"`
	Ldap       *ldap.Config   `json:"ldap,omitempty" xml:"ldap" yaml:"ldap,omitempty"`
	Saml       *saml.Config   `json:"saml,omitempty" xml:"saml" yaml:"saml,omitempty"`
	OAuth2     *oauth2.Config `json:"oauth2,omitempty" xml:"oauth2" yaml:"oauth2,omitempty"`
	authMethod AuthMethodType
}

// Backend is an authentication backend.
type Backend struct {
	Method AuthMethodType
	driver BackendDriver
	logger *zap.Logger
}

// BackendDriver is an interface to an authentication provider.
type BackendDriver interface {
	GetRealm() string
	GetName() string
	GetMethod() string
	GetConfig() string
	Configure() error
	Validate() error
	Request(operator.Type, *requests.Request) error
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

// GetConfig returns Backend configuration.
func (b *Backend) GetConfig() string {
	return b.driver.GetConfig()
}

// Configure configures backend with the authentication provider settings.
func (b *Backend) Configure() error {
	return b.driver.Configure()
}

// Request performs the requested backend operation.
func (b *Backend) Request(op operator.Type, r *requests.Request) error {
	return b.driver.Request(op, r)
}

// Validate checks whether an authentication provider is functional.
func (b *Backend) Validate() error {
	return b.driver.Validate()
}

// NewBackend returns Backend instance.
func NewBackend(cfg *Config, logger *zap.Logger) (*Backend, error) {
	if logger == nil {
		return nil, errors.ErrBackendConfigureLoggerNotFound
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	b := &Backend{
		Method: cfg.authMethod,
		logger: logger,
	}

	switch cfg.authMethod {
	case Local:
		b.driver = local.NewDatabaseBackend(cfg.Local, logger)
	case Ldap:
		b.driver = ldap.NewDatabaseBackend(cfg.Ldap, logger)
	case Saml:
		b.driver = saml.NewDatabaseBackend(cfg.Saml, logger)
	case OAuth2:
		b.driver = oauth2.NewDatabaseBackend(cfg.OAuth2, logger)
	}
	return b, nil
}

// NewConfig returns Config instance.
func NewConfig(m map[string]interface{}) (*Config, error) {
	if m == nil {
		return nil, errors.ErrBackendNewConfig.WithArgs(m, "invalid config")
	}
	if _, exists := m["method"]; !exists {
		return nil, errors.ErrBackendNewConfig.WithArgs(m, "auth method not found")
	}
	b, _ := json.Marshal(m)
	cfg := &Config{}
	switch m["method"] {
	case "local":
		cfg.Local = &local.Config{}
		if err := json.Unmarshal(b, cfg.Local); err != nil {
			return nil, errors.ErrBackendNewConfig.WithArgs(m, err)
		}
		cfg.authMethod = Local
	case "ldap":
		cfg.Ldap = &ldap.Config{}
		if err := json.Unmarshal(b, cfg.Ldap); err != nil {
			return nil, errors.ErrBackendNewConfig.WithArgs(m, err)
		}
		cfg.authMethod = Ldap
	case "saml":
		cfg.Saml = &saml.Config{}
		if err := json.Unmarshal(b, cfg.Saml); err != nil {
			return nil, errors.ErrBackendNewConfig.WithArgs(m, err)
		}
		cfg.authMethod = Saml
	case "oauth2":
		cfg.OAuth2 = &oauth2.Config{}
		if err := json.Unmarshal(b, cfg.OAuth2); err != nil {
			return nil, errors.ErrBackendNewConfig.WithArgs(m, err)
		}
		cfg.authMethod = OAuth2
	default:
		return nil, errors.ErrBackendNewConfigInvalidAuthMethod.WithArgs(m)
	}
	return cfg, nil
}

func (c *Config) validate() error {
	enabledMethods := []string{}
	methods := make(map[string]string)
	if c.Local != nil {
		methods["local"] = c.Local.Method
		enabledMethods = append(enabledMethods, "local")
	}
	if c.Ldap != nil {
		methods["ldap"] = c.Ldap.Method
		enabledMethods = append(enabledMethods, "ldap")
	}
	if c.Saml != nil {
		methods["saml"] = c.Saml.Method
		enabledMethods = append(enabledMethods, "saml")
	}
	if c.OAuth2 != nil {
		methods["oauth2"] = c.OAuth2.Method
		enabledMethods = append(enabledMethods, "oauth2")
	}
	for k, v := range methods {
		if k != v {
			return errors.ErrBackendConfigureInvalidMethod.WithArgs(k, v)
		}
	}
	switch len(enabledMethods) {
	case 0:
		return errors.ErrBackendConfigureEmptyConfig
	case 1:
	default:
		return errors.ErrBackendConfigureMultipleMethods.WithArgs(enabledMethods)
	}

	switch enabledMethods[0] {
	case "local":
		c.authMethod = Local
	case "ldap":
		c.authMethod = Ldap
	case "saml":
		c.authMethod = Saml
	case "oauth2":
		c.authMethod = OAuth2
	}
	return nil
}

// String returns the description for AuthMethodType enum.
func (m AuthMethodType) String() string {
	switch m {
	case Unknown:
		return "Unknown"
	case Local:
		return "Local"
	case Ldap:
		return "LDAP"
	case Saml:
		return "SAML"
	case OAuth2:
		return "OAuth 2.0"
	}
	return fmt.Sprintf("AuthMethodType(%d)", int(m))
}
