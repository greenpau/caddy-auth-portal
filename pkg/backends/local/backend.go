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

package local

import (
	"github.com/greenpau/caddy-auth-portal/pkg/enums/operator"
	"github.com/greenpau/caddy-auth-portal/pkg/errors"
	"github.com/greenpau/go-identity/pkg/requests"
	"go.uber.org/zap"
	"strings"
)

// Config holds the configuration for the backend.
type Config struct {
	Name   string `json:"name,omitempty"`
	Method string `json:"method,omitempty"`
	Realm  string `json:"realm,omitempty"`
	Path   string `json:"path,omitempty"`
}

// Backend represents authentication provider with local backend.
type Backend struct {
	config        *Config        `json:"-"`
	authenticator *Authenticator `json:"-"`
	logger        *zap.Logger
}

// NewDatabaseBackend return an instance of authentication provider
// with local backend.
func NewDatabaseBackend(cfg *Config, logger *zap.Logger) *Backend {
	b := &Backend{
		config: cfg,
		logger: logger,
	}
	return b
}

// GetRealm return authentication realm.
func (b *Backend) GetRealm() string {
	return b.config.Realm
}

// GetName return the name associated with this backend.
func (b *Backend) GetName() string {
	return b.config.Name
}

// GetMethod returns the authentication method associated with this backend.
func (b *Backend) GetMethod() string {
	return b.config.Method
}

// Request performs the requested backend operation.
func (b *Backend) Request(op operator.Type, r *requests.Request) error {
	switch op {
	case operator.Authenticate:
		return b.Authenticate(r)
	case operator.ChangePassword:
		return b.authenticator.ChangePassword(r)
	case operator.AddKeySSH:
		return b.authenticator.AddPublicKey(r)
	case operator.AddKeyGPG:
		return b.authenticator.AddPublicKey(r)
	case operator.DeletePublicKey:
		return b.authenticator.DeletePublicKey(r)
	case operator.AddMfaToken:
		// b.logger.Debug("detected supported backend operation", zap.Any("op", op), zap.Any("params", r))
		return b.authenticator.AddMfaToken(r)
	case operator.DeleteMfaToken:
		return b.authenticator.DeleteMfaToken(r)
	case operator.GetPublicKeys:
		return b.authenticator.GetPublicKeys(r)
	case operator.GetMfaTokens:
		return b.authenticator.GetMfaTokens(r)
	case operator.AddUser:
		return b.authenticator.AddUser(r)
	case operator.GetUsers:
		return b.authenticator.GetUsers(r)
	case operator.GetUser:
		return b.authenticator.GetUser(r)
	case operator.DeleteUser:
		return b.authenticator.DeleteUser(r)
	}

	b.logger.Error(
		"detected unsupported backend operation",
		zap.Any("op", op),
		zap.Any("params", r),
	)
	return errors.ErrOperatorNotSupported.WithArgs(op)
}

// Configure configures Backend.
func (b *Backend) Configure() error {
	if b.config.Name == "" {
		return errors.ErrBackendConfigureNameEmpty
	}
	if b.config.Method == "" {
		return errors.ErrBackendConfigureMethodEmpty
	}
	if b.config.Realm == "" {
		return errors.ErrBackendConfigureRealmEmpty
	}
	if b.config.Path == "" {
		return errors.ErrBackendLocalConfigurePathEmpty
	}

	if b.authenticator == nil {
		if v, exists := globalAuthenticators[b.config.Realm]; exists {
			if b.config.Path != v.path {
				return errors.ErrBackendLocalConfigurePathMismatch.WithArgs(b.config.Path, v.path)
			}
			b.authenticator = v
		} else {
			b.authenticator = NewAuthenticator()
			globalAuthenticators[b.config.Realm] = b.authenticator
		}
	}
	b.authenticator.logger = b.logger
	return b.authenticator.Configure(b.config.Path)
}

// Validate checks whether Backend is functional.
func (b *Backend) Validate() error {
	b.logger.Info(
		"validating local backend",
		zap.String("db_path", b.config.Path),
	)
	return nil
}

// GetConfig returns Backend configuration.
func (b *Backend) GetConfig() string {
	var sb strings.Builder
	sb.WriteString("name " + b.config.Name + "\n")
	sb.WriteString("method " + b.config.Method + "\n")
	sb.WriteString("realm " + b.config.Realm + "\n")
	sb.WriteString("path " + b.config.Path + "")
	return sb.String()
}

// Authenticate performs authentication.
func (b *Backend) Authenticate(r *requests.Request) error {
	if err := b.authenticator.AuthenticateUser(r); err != nil {
		return errors.ErrBackendLocalAuthFailed.WithArgs(err)
	}
	return nil
}
