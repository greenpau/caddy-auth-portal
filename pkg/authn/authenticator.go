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

package authn

import (
	"time"

	"github.com/greenpau/caddy-auth-portal/pkg/backends"
	"github.com/greenpau/caddy-auth-portal/pkg/cache"
	"github.com/greenpau/caddy-auth-portal/pkg/cookie"
	"github.com/greenpau/caddy-auth-portal/pkg/registration"
	"github.com/greenpau/caddy-auth-portal/pkg/transformer"
	"github.com/greenpau/caddy-auth-portal/pkg/ui"
	"github.com/greenpau/caddy-authorize/pkg/acl"
	"github.com/greenpau/caddy-authorize/pkg/kms"
	"github.com/greenpau/caddy-authorize/pkg/options"
	"github.com/greenpau/caddy-authorize/pkg/validator"
	"github.com/greenpau/go-identity"
	"go.uber.org/zap"
)

// var sandboxCache *cache.SandboxCache
// func init() {
//	sandboxCache, _ = cache.NewSandboxCache(nil)
// }

// Authenticator implements Form-Based, Basic, Local, LDAP,
// OpenID Connect, OAuth 2.0, SAML Authentication.
type Authenticator struct {
	Name string `json:"-"`
	// PrimaryInstance indicates, when it is set to true, the instance of the
	// portal is primary.
	PrimaryInstance bool `json:"primary,omitempty"`
	// Context is the context whether the portal operates.
	Context string `json:"context,omitempty"`
	// UI holds the configuration for the user interface.
	UI *ui.Parameters `json:"ui,omitempty"`
	// UserRegistrationConfig holds the configuration for the user registration.
	UserRegistrationConfig *registration.Config `json:"user_registration_config,omitempty" xml:"user_registration_config,omitempty" yaml:"user_registration_config,omitempty"`
	// UserTransformerConfig holds the configuration for the user transformer.
	UserTransformerConfigs []*transformer.Config `json:"user_transformer_config,omitempty" xml:"user_transformer_config,omitempty" yaml:"user_transformer_config,omitempty"`
	// CookieConfig holds the configuration for the cookies issues by Authenticator.
	CookieConfig *cookie.Config `json:"cookie_config,omitempty" xml:"cookie_config,omitempty" yaml:"cookie_config,omitempty"`
	// BackendConfigs hold the configurations for authentication backends.
	BackendConfigs []backends.Config `json:"backend_configs,omitempty"`
	// AccessListConfigs hold the configurations for the ACL of the token validator.
	AccessListConfigs []*acl.RuleConfiguration `json:"access_list_configs,omitempty"`
	// TokenValidatorOptions holds the configuration for the token validator.
	TokenValidatorOptions *options.TokenValidatorOptions `json:"token_validator_options,omitempty"`
	// CryptoKeyConfigs hold the configurations for the keys used to issue and validate user tokens.
	CryptoKeyConfigs []*kms.CryptoKeyConfig `json:"crypto_key_configs,omitempty"`
	// CryptoKeyStoreConfig hold the default configuration for the keys, e.g. token name and lifetime.
	CryptoKeyStoreConfig map[string]interface{} `json:"crypto_key_store_config,omitempty"`
	// TokenGrantorOptions holds the configuration for the tokens issues by Authenticator.
	TokenGrantorOptions *options.TokenGrantorOptions `json:"token_grantor_options,omitempty"`
	// CacheConfig holds the configuration to instantiate a cache backend
	CacheConfig *cache.Config

	registrar    *identity.Database
	validator    *validator.TokenValidator
	keystore     *kms.CryptoKeyStore
	backends     []*backends.Backend
	cookie       *cookie.Factory
	transformer  *transformer.Factory
	logger       *zap.Logger
	ui           *ui.Factory
	startedAt    time.Time
	cache        cache.Cache
	loginOptions map[string]interface{}
}

// SetLogger add logger to Authenticator.
func (m *Authenticator) SetLogger(logger *zap.Logger) {
	m.logger = logger
}

// Provision configures the instance of authentication portal.
func (m *Authenticator) Provision() error {
	m.startedAt = time.Now().UTC()
	/*
		TODO(greenpau): remove
		if sandboxCache == nil {
			return fmt.Errorf(
				"authentication provider registration error, instance %s, error: %s",
				m.Name, "sandbox cache is nil",
			)
		}
	*/
	if err := AuthManager.Register(m); err != nil {
		return err
	}
	m.logger.Info(
		"provisioned plugin instance",
		zap.String("instance_name", m.Name),
		zap.Time("started_at", m.startedAt),
	)
	return nil
}

// Validate validates the provisioning.
func (m *Authenticator) Validate() error {
	if err := AuthManager.Validate(m); err != nil {
		return err
	}
	m.logger.Info(
		"validated plugin instance",
		zap.String("instance_name", m.Name),
	)
	return nil
}
