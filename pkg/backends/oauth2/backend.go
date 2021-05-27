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

package oauth2

import (
	"crypto/rsa"
	//"encoding/base64"

	"github.com/greenpau/caddy-auth-portal/pkg/enums/operator"
	"github.com/greenpau/caddy-auth-portal/pkg/errors"
	"github.com/greenpau/go-identity/pkg/requests"
	"go.uber.org/zap"
	"time"
)

// Backend represents authentication provider with OAuth 2.0 backend.
type Backend struct {
	Config                 *Config
	metadata               map[string]interface{}
	keys                   map[string]*JwksKey
	publicKeys             map[string]*rsa.PublicKey
	authorizationURL       string
	tokenURL               string
	keysURL                string
	lastKeyFetch           time.Time
	keyFetchAttempts       int
	disableKeyVerification bool
	disablePassGrantType   bool
	disableResponseType    bool
	disableNonce           bool
	disableScope           bool
	enableAcceptHeader     bool
	enableBodyDecoder      bool
	requiredTokenFields    map[string]interface{}
	// state stores cached state IDs
	state  *stateManager
	logger *zap.Logger
}

// NewDatabaseBackend return an instance of authentication provider
// with OAuth 2.0 backend.
func NewDatabaseBackend(cfg *Config, logger *zap.Logger) *Backend {
	b := &Backend{
		Config:     cfg,
		state:      newStateManager(),
		keys:       make(map[string]*JwksKey),
		publicKeys: make(map[string]*rsa.PublicKey),
		requiredTokenFields: map[string]interface{}{
			"access_token": true,
			"id_token":     true,
		},
		logger: logger,
	}
	go manageStateManager(b.state)
	return b
}

// GetRealm return authentication realm.
func (b *Backend) GetRealm() string {
	return b.Config.Realm
}

// GetName return the name associated with this backend.
func (b *Backend) GetName() string {
	return b.Config.Name
}

// GetMethod returns the authentication method associated with this backend.
func (b *Backend) GetMethod() string {
	return b.Config.Method
}

// Request performs the requested backend operation.
func (b *Backend) Request(op operator.Type, r *requests.Request) error {
	switch op {
	case operator.Authenticate:
		return b.Authenticate(r)
	}
	return errors.ErrOperatorNotSupported.WithArgs(op)
}
