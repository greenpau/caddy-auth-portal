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

package local

import (
	"github.com/greenpau/go-identity"
	"github.com/greenpau/go-identity/pkg/requests"
	"github.com/satori/go.uuid"
	"go.uber.org/zap"
	"sync"
)

var globalAuthenticators map[string]*Authenticator

func init() {
	globalAuthenticators = make(map[string]*Authenticator)
}

// Authenticator represents database connector.
type Authenticator struct {
	db     *identity.Database
	mux    sync.Mutex
	path   string
	logger *zap.Logger
}

// NewAuthenticator returns an instance of Authenticator.
func NewAuthenticator() *Authenticator {
	return &Authenticator{}
}

// Configure check database connectivity and required tables.
func (sa *Authenticator) Configure(fp string) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	sa.logger.Info(
		"local backend configuration",
		zap.String("db_path", fp),
	)
	sa.path = fp

	db, err := identity.NewDatabase(fp)
	if err != nil {
		return err
	}
	sa.db = db
	if len(sa.db.Users) == 0 {
		req := &requests.Request{
			User: requests.User{
				Username: "webadmin",
				Password: uuid.NewV4().String(),
				Email:    "webadmin@localdomain.local",
				Roles:    []string{"superadmin"},
			},
		}
		if err := sa.db.AddUser(req); err != nil {
			return err
		}
		sa.logger.Info("created default superadmin user for the database",
			zap.String("username", req.User.Username),
			zap.String("email", req.User.Email),
			zap.String("secret", req.User.Password),
			zap.Any("roles", req.User.Roles),
		)
	}
	return nil
}

// AuthenticateUser checks the database for the presence of a username/email
// and password and returns user claims.
func (sa *Authenticator) AuthenticateUser(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.AuthenticateUser(r)
}

// AddUser adds a user to database.
func (sa *Authenticator) AddUser(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.AddUser(r)
}

// GetUsers retrieves users from database.
func (sa *Authenticator) GetUsers(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.GetUsers(r)
}

// GetUser retrieves a specific user from database.
func (sa *Authenticator) GetUser(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.GetUser(r)
}

// DeleteUser delete a specific user from database.
func (sa *Authenticator) DeleteUser(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.DeleteUser(r)
}

// ChangePassword changes password for a user.
func (sa *Authenticator) ChangePassword(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.ChangeUserPassword(r)
}

// AddPublicKey adds public key, e.g. GPG or SSH, for a user.
func (sa *Authenticator) AddPublicKey(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.AddPublicKey(r)
}

// DeletePublicKey removes a public key, e.g. GPG or SSH, associated with the user.
func (sa *Authenticator) DeletePublicKey(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.DeletePublicKey(r)
}

// GetPublicKeys returns a list of public keys associated with a user.
func (sa *Authenticator) GetPublicKeys(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.GetPublicKeys(r)
}

// AddMfaToken adds MFA token to a user.
func (sa *Authenticator) AddMfaToken(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.AddMfaToken(r)
}

// DeleteMfaToken removes MFA token associated with the user.
func (sa *Authenticator) DeleteMfaToken(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.DeleteMfaToken(r)
}

// GetMfaTokens returns a list of MFA token associated with a user.
func (sa *Authenticator) GetMfaTokens(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.GetMfaTokens(r)
}
