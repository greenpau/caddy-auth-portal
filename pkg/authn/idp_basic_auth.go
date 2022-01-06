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
	"context"
	"encoding/base64"
	"github.com/greenpau/caddy-auth-portal/pkg/enums/operator"
	"github.com/greenpau/caddy-authorize/pkg/errors"
	"github.com/greenpau/caddy-authorize/pkg/shared/idp"
	"github.com/greenpau/caddy-authorize/pkg/user"
	"github.com/greenpau/go-identity/pkg/requests"
	"go.uber.org/zap"
	"strings"
	"time"
)

// BasicAuth performs API key authentication.
func (p *Authenticator) BasicAuth(r *idp.ProviderRequest) error {
	if r.Realm == "" {
		r.Realm = "local"
	}

	rr := requests.NewRequest()
	rr.Logger = p.logger
	rr.Response.Authenticated = false
	rr.Upstream.Realm = r.Realm

	arr, err := base64.StdEncoding.DecodeString(r.Secret)
	if err != nil {
		p.logger.Warn(
			"failed to decode credentials",
			zap.String("source_address", r.Address),
			zap.String("custom_auth", "basicauth"),
			zap.String("realm", r.Realm),
			zap.Error(err),
		)
		return errors.ErrBasicAuthFailed
	}

	creds := strings.SplitN(string(arr), ":", 2)
	rr.User.Username = creds[0]
	rr.User.Password = creds[1]

	backend := p.getBackendByRealm(r.Realm)
	if backend == nil {
		p.logger.Warn(
			"realm backend not found",
			zap.String("source_address", r.Address),
			zap.String("custom_auth", "basicauth"),
			zap.String("realm", r.Realm),
		)
		return errors.ErrBasicAuthFailed
	}

	/*
		if err := backend.Request(operator.LookupBasic, rr); err != nil {
			p.logger.Warn(
				"api key lookup failed",
				zap.String("source_address", r.Address),
				zap.String("custom_auth", "basicauth"),
				zap.String("realm", r.Realm),
				zap.Error(err),
			)
			return errors.ErrBasicAuthFailed
		}
	*/

	if err := backend.Request(operator.IdentifyUser, rr); err != nil {
		p.logger.Warn(
			"user lookup failed",
			zap.String("source_address", r.Address),
			zap.String("custom_auth", "basicauth"),
			zap.String("realm", r.Realm),
			zap.Error(err),
		)
		return errors.ErrBasicAuthFailed
	}

	if len(rr.User.Challenges) != 1 {
		p.logger.Warn(
			"user lookup failed",
			zap.String("source_address", r.Address),
			zap.String("custom_auth", "basicauth"),
			zap.String("realm", r.Realm),
			zap.String("error", "detected too many auth challenges"),
		)
		return errors.ErrBasicAuthFailed
	}

	if rr.User.Challenges[0] != "password" {
		p.logger.Warn(
			"user lookup failed",
			zap.String("source_address", r.Address),
			zap.String("custom_auth", "basicauth"),
			zap.String("realm", r.Realm),
			zap.String("error", "detected unsupported auth challenges"),
		)
		return errors.ErrBasicAuthFailed
	}

	if err := backend.Request(operator.Authenticate, rr); err != nil {
		p.logger.Warn(
			"user authentication failed",
			zap.String("source_address", r.Address),
			zap.String("custom_auth", "basicauth"),
			zap.String("realm", r.Realm),
			zap.Error(err),
		)
		return errors.ErrBasicAuthFailed
	}

	m := make(map[string]interface{})
	m["sub"] = rr.User.Username
	m["email"] = rr.User.Email
	if rr.User.FullName != "" {
		m["name"] = rr.User.FullName
	}
	if len(rr.User.Roles) > 0 {
		m["roles"] = rr.User.Roles
	}

	// m["jti"] = rr.Upstream.SessionID
	m["exp"] = time.Now().Add(time.Duration(p.keystore.GetTokenLifetime(nil, nil)) * time.Second).UTC().Unix()
	m["iat"] = time.Now().UTC().Unix()
	m["nbf"] = time.Now().Add(time.Duration(60)*time.Second*-1).UTC().Unix() * 1000
	if _, exists := m["origin"]; !exists {
		m["origin"] = r.Realm
	}
	m["iss"] = "authp"
	m["addr"] = r.Address

	// Perform user claim transformation if necessary.
	if err := p.transformUser(context.Background(), rr, m); err != nil {
		return err
	}

	// Inject portal specific roles
	injectPortalRoles(m)

	// Create a new user and sign the token.
	usr, err := user.NewUser(m)
	if err != nil {
		p.logger.Warn(
			"user build following user lookup failed",
			zap.String("source_address", r.Address),
			zap.String("custom_auth", "basicauth"),
			zap.String("realm", r.Realm),
			zap.Error(err),
		)
		return errors.ErrBasicAuthFailed
	}
	if err := p.keystore.SignToken(nil, nil, usr); err != nil {
		p.logger.Warn(
			"user token signing failed",
			zap.String("source_address", r.Address),
			zap.String("custom_auth", "basicauth"),
			zap.String("realm", r.Realm),
			zap.Error(err),
		)
		return errors.ErrBasicAuthFailed
	}

	r.Response.Payload = usr.Token
	r.Response.Name = usr.TokenName
	return nil
}
