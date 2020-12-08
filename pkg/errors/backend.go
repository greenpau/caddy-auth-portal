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

package errors

// Backend errors.
const (
	ErrBackendConfigureOptionNotFound StandardError = "backend configuration option %s not found"
	ErrBackendConfigureOptionNilValue StandardError = "backend configuration option %s has nil value"

	ErrBackendOauthAuthorizationStateNotFound StandardError = "OAuth 2.0 authorization state not found"
	ErrBackendRealmNotFound                   StandardError = "no realm found for provider %s"
	ErrBackendClientIDNotFound                StandardError = "no client_id found for provider %s"
	ErrBackendClientSecretNotFound            StandardError = "no client_secret found for provider %s"
	ErrBackendInvalidIdentityTokenName        StandardError = "invalid identity token name %s for provider %s"
	ErrBackendServerIDNotFound                StandardError = "no server_id found for provider %s"
	ErrBackendAppNameNotFound                 StandardError = "no application name found for provider %s"

	ErrBackendUnsupportedProvider           StandardError = "unsupported OAuth 2.0 provider %s"
	ErrBackendOauthProviderNotFound         StandardError = "no OAuth 2.0 provider found for provider %s"
	ErrBackendOauthAuthorizationURLNotFound StandardError = "authorization URL not found for provider %s"

	ErrBackendOauthMetadataFetchFailed         StandardError = "failed to fetch metadata for OAuth 2.0 authorization server: %s"
	ErrBackendOauthKeyFetchFailed              StandardError = "failed to fetch jwt keys for OAuth 2.0 authorization server: %s"
	ErrBackendOauthAuthorizationFailedDetailed StandardError = "failed OAuth 2.0 authorization flow, error: %s, description: %s"
	ErrBackendOauthAuthorizationFailed         StandardError = "failed OAuth 2.0 authorization flow, error: %s"

	ErrBackendOauthFetchAccessTokenFailed StandardError = "failed fetching OAuth 2.0 access token: %s"

	ErrBackendOauthFetchClaimsFailed StandardError = "failed fetching OAuth 2.0 claims: %s"

	ErrBackendOauthValidateAccessTokenFailed StandardError = "failed validating OAuth 2.0 access token: %s"

	ErrBackendOauthResponseProcessingFailed StandardError = "unable to process OAuth 2.0 response"

	ErrBackendLoggerNotFound        StandardError = "%s backend logger is nil"
	ErrBackendTokenProviderNotFound StandardError = "upstream token provider is nil"

	ErrBackendUpstreamLoggerNotFound StandardError = "upstream logger is nil"

	ErrBackendOauthMetadataFieldNotFound StandardError = "metadata %s field not found for provider %s"

	ErrBackendOauthJwksResponseKeysNotFound StandardError = "jwks response has no keys field"

	ErrBackendOauthJwksKeysParseFailed StandardError = "failed to compile jwks keys into JSON: %s"

	ErrBackendOauthJwksKeysNotFound StandardError = "no jwks keys found"

	ErrBackendOauthJwksInvalidKey StandardError = "invalid jwks key: %s"

	ErrBackendOauthGetAccessTokenFailedDetailed StandardError = "failed obtaining OAuth 2.0 access token, error: %s, description: %s"
	ErrBackendOauthGetAccessTokenFailed         StandardError = "failed obtaining OAuth 2.0 access token, error: %s"

	ErrBackendAuthorizationServerResponseFieldNotFound StandardError = "authorization server response has no %s field"

	ErrBackendOauthJwksKeysTooManyAttempts StandardError = "too many attemps to fetch jwks keys"
)
