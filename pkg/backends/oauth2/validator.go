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

package oauth2

import (
	jwtlib "github.com/golang-jwt/jwt/v4"
	"github.com/greenpau/caddy-auth-portal/pkg/errors"
)

var (
	tokenFields = []string{
		"sub", "name", "email", "iat", "exp", "jti",
		"iss", "groups", "picture",
		"roles", "role", "groups", "group",
	}
)

func (b *Backend) validateAccessToken(state string, data map[string]interface{}) (map[string]interface{}, error) {
	var tokenString string
	if v, exists := data[b.Config.IdentityTokenName]; exists {
		tokenString = v.(string)
	} else {
		return nil, errors.ErrBackendOAuthAccessTokenNotFound.WithArgs(b.Config.IdentityTokenName)
	}

	token, err := jwtlib.Parse(tokenString, func(token *jwtlib.Token) (interface{}, error) {
		if _, validMethod := token.Method.(*jwtlib.SigningMethodRSA); !validMethod {
			return nil, errors.ErrBackendOAuthAccessTokenSignMethodNotSupported.WithArgs(b.Config.IdentityTokenName, token.Header["alg"])
		}
		keyID, found := token.Header["kid"].(string)
		if !found {
			return nil, errors.ErrBackendOAuthAccessTokenKeyIDNotFound.WithArgs(b.Config.IdentityTokenName)
		}
		key, exists := b.publicKeys[keyID]
		if !exists {
			if !b.disableKeyVerification {
				if err := b.fetchKeysURL(); err != nil {
					return nil, errors.ErrBackendOauthKeyFetchFailed.WithArgs(err)
				}
			}
			key, exists = b.publicKeys[keyID]
			if !exists {
				return nil, errors.ErrBackendOAuthAccessTokenKeyIDNotRegistered.WithArgs(b.Config.IdentityTokenName, keyID)
			}
		}
		return key, nil
	})

	if err != nil {
		return nil, errors.ErrBackendOAuthParseToken.WithArgs(b.Config.IdentityTokenName, err)
	}

	if _, ok := token.Claims.(jwtlib.Claims); !ok && !token.Valid {
		return nil, errors.ErrBackendOAuthInvalidToken.WithArgs(b.Config.IdentityTokenName, tokenString)
	}
	claims := token.Claims.(jwtlib.MapClaims)
	if _, exists := claims["nonce"]; !exists {
		return nil, errors.ErrBackendOAuthNonceValidationFailed.WithArgs(b.Config.IdentityTokenName, "nonce not found")
	}
	if err := b.state.validateNonce(state, claims["nonce"].(string)); err != nil {
		return nil, errors.ErrBackendOAuthNonceValidationFailed.WithArgs(b.Config.IdentityTokenName, err)
	}

	if _, exists := claims["email"]; !exists {
		return nil, errors.ErrBackendOAuthEmailNotFound.WithArgs(b.Config.IdentityTokenName)
	}

	m := make(map[string]interface{})
	for _, k := range tokenFields {
		if _, exists := claims[k]; !exists {
			continue
		}
		m[k] = claims[k]
	}
	return m, nil
}
