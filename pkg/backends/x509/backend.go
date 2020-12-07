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

package x509

import (
	"fmt"
	"sync"

	jwtconfig "github.com/greenpau/caddy-auth-jwt/pkg/config"
	"github.com/greenpau/go-identity"

	"go.uber.org/zap"
)

var (
	globalAuthenticator *Authenticator
)

func init() {
	globalAuthenticator = NewAuthenticator()
	return
}

// Backend represents authentication provider with X.509 backend.
type Backend struct {
	Name          string                       `json:"name,omitempty"`
	Method        string                       `json:"method,omitempty"`
	Realm         string                       `json:"realm,omitempty"`
	TokenProvider *jwtconfig.CommonTokenConfig `json:"-"`
	Authenticator *Authenticator               `json:"-"`
	logger        *zap.Logger
}

// NewDatabaseBackend return an instance of authentication provider
// with X.509 backend.
func NewDatabaseBackend() *Backend {
	b := &Backend{
		Method:        "x509",
		TokenProvider: jwtconfig.NewCommonTokenConfig(),
		Authenticator: globalAuthenticator,
	}
	return b
}

// Authenticator represents database connector.
type Authenticator struct {
	mux    sync.Mutex
	realm  string
	logger *zap.Logger
}

// NewAuthenticator returns an instance of Authenticator.
func NewAuthenticator() *Authenticator {
	return &Authenticator{}
}

// ConfigureRealm configures a domain name (realm) associated with
// the instance of authenticator.
func (sa *Authenticator) ConfigureRealm(realm string) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	if realm == "" {
		return fmt.Errorf("no realm found")
	}
	sa.realm = realm
	sa.logger.Info(
		"X.509 plugin configuration",
		zap.String("phase", "realm"),
		zap.String("realm", realm),
	)
	return nil
}

// ConfigureAuthenticator configures backend for .
func (b *Backend) ConfigureAuthenticator() error {
	if b.Authenticator == nil {
		b.Authenticator = NewAuthenticator()
	}

	b.Authenticator.logger = b.logger

	if err := b.Authenticator.ConfigureRealm(b.Realm); err != nil {
		b.logger.Error("failed configuring realm (domain) for X.509 authentication",
			zap.String("error", err.Error()))
		return err
	}

	return nil
}

// ValidateConfig checks whether Backend has mandatory configuration.
func (b *Backend) ValidateConfig() error {
	return nil
}

// Authenticate performs authentication.
func (b *Backend) Authenticate(opts map[string]interface{}) (map[string]interface{}, error) {
	resp := make(map[string]interface{})
	resp["code"] = 400
	return resp, fmt.Errorf("unsupported backend %s", b.Name)
}

// Validate checks whether Backend is functional.
func (b *Backend) Validate() error {
	if err := b.ValidateConfig(); err != nil {
		return err
	}
	if b.logger == nil {
		return fmt.Errorf("X.509 backend logger is nil")
	}

	b.logger.Info("validating X.509 backend")

	if b.Authenticator == nil {
		return fmt.Errorf("X.509 authenticator is nil")
	}

	b.logger.Info("successfully validated X.509 backend")
	return nil
}

// GetRealm return authentication realm.
func (b *Backend) GetRealm() string {
	return b.Realm
}

// GetName return the name associated with this backend.
func (b *Backend) GetName() string {
	return b.Name
}

// ConfigureTokenProvider configures TokenProvider.
func (b *Backend) ConfigureTokenProvider(upstream *jwtconfig.CommonTokenConfig) error {
	if upstream == nil {
		return fmt.Errorf("upstream token provider is nil")
	}
	if b.TokenProvider == nil {
		b.TokenProvider = jwtconfig.NewCommonTokenConfig()
	}
	if b.TokenProvider.TokenSecret == "" {
		b.TokenProvider.TokenSecret = upstream.TokenSecret
	}
	if b.TokenProvider.TokenOrigin == "" {
		b.TokenProvider.TokenOrigin = upstream.TokenOrigin
	}
	b.TokenProvider.TokenLifetime = upstream.TokenLifetime
	b.TokenProvider.TokenName = upstream.TokenName
	return nil
}

// ConfigureLogger configures backend with the same logger as its user.
func (b *Backend) ConfigureLogger(logger *zap.Logger) error {
	if logger == nil {
		return fmt.Errorf("upstream logger is nil")
	}
	b.logger = logger
	return nil
}

// GetMethod returns the authentication method associated with this backend.
func (b *Backend) GetMethod() string {
	return b.Method
}

// Do performs the requested operation.
func (b *Backend) Do(opts map[string]interface{}) error {
	op := opts["name"].(string)
	switch op {
	case "password_change":
		return fmt.Errorf("Password change operation is not available")
	}
	return fmt.Errorf("Unsupported backend operation")
}

// GetPublicKeys return a list of public keys associated with a user.
func (b *Backend) GetPublicKeys(opts map[string]interface{}) ([]*identity.PublicKey, error) {
	return nil, fmt.Errorf("Unsupported backend operation")
}

// GetMfaTokens return a list of MFA tokens associated with a user.
func (b *Backend) GetMfaTokens(opts map[string]interface{}) ([]*identity.MfaToken, error) {
	return nil, fmt.Errorf("Unsupported backend operation")
}
