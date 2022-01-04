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

package errors

// Backend errors.
const (
	ErrBackendConfigureOptionNotFound                  StandardError = "backend configuration option %s not found"
	ErrBackendConfigureOptionNilValue                  StandardError = "backend configuration option %s has nil value"
	ErrBackendOauthAuthorizationStateNotFound          StandardError = "OAuth 2.0 authorization state not found"
	ErrBackendClientIDNotFound                         StandardError = "no client_id found for provider %s"
	ErrBackendClientSecretNotFound                     StandardError = "no client_secret found for provider %s"
	ErrBackendInvalidIdentityTokenName                 StandardError = "invalid identity token name %s for provider %s"
	ErrBackendServerIDNotFound                         StandardError = "no server_id found for provider %s"
	ErrBackendAppNameNotFound                          StandardError = "no application name found for provider %s"
	ErrBackendUnsupportedProvider                      StandardError = "unsupported OAuth 2.0 provider %s"
	ErrBackendOauthProviderNotFound                    StandardError = "no OAuth 2.0 provider found for provider %s"
	ErrBackendOauthAuthorizationURLNotFound            StandardError = "authorization URL not found for provider %s"
	ErrBackendOauthMetadataFetchFailed                 StandardError = "failed to fetch metadata for OAuth 2.0 authorization server: %s"
	ErrBackendOauthKeyFetchFailed                      StandardError = "failed to fetch jwt keys for OAuth 2.0 authorization server: %s"
	ErrBackendOauthAuthorizationFailedDetailed         StandardError = "failed OAuth 2.0 authorization flow, error: %s, description: %s"
	ErrBackendOauthAuthorizationFailed                 StandardError = "failed OAuth 2.0 authorization flow, error: %s"
	ErrBackendOauthFetchAccessTokenFailed              StandardError = "failed fetching OAuth 2.0 access token: %s"
	ErrBackendOauthFetchClaimsFailed                   StandardError = "failed fetching OAuth 2.0 claims: %s"
	ErrBackendOauthFetchUserGroupsFailed               StandardError = "failed fetching OAuth 2.0 user groups: %v"
	ErrBackendOauthValidateAccessTokenFailed           StandardError = "failed validating OAuth 2.0 access token: %s"
	ErrBackendOauthResponseProcessingFailed            StandardError = "unable to process OAuth 2.0 response"
	ErrBackendLoggerNotFound                           StandardError = "%s backend logger is nil"
	ErrBackendTokenProviderNotFound                    StandardError = "upstream token provider is nil"
	ErrBackendUpstreamLoggerNotFound                   StandardError = "upstream logger is nil"
	ErrBackendOauthMetadataFieldNotFound               StandardError = "metadata %s field not found for provider %s"
	ErrBackendOauthJwksResponseKeysNotFound            StandardError = "jwks response has no keys field"
	ErrBackendOauthJwksKeysParseFailed                 StandardError = "failed to compile jwks keys into JSON: %v"
	ErrBackendOauthJwksKeysNotFound                    StandardError = "no jwks keys found"
	ErrBackendOauthJwksInvalidKey                      StandardError = "invalid jwks key: %v"
	ErrBackendOauthGetAccessTokenFailedDetailed        StandardError = "failed obtaining OAuth 2.0 access token, error: %v, description: %q"
	ErrBackendOauthGetAccessTokenFailed                StandardError = "failed obtaining OAuth 2.0 access token, error: %v"
	ErrBackendAuthorizationServerResponseFieldNotFound StandardError = "authorization server response has no %q field"
	ErrBackendOauthJwksKeysTooManyAttempts             StandardError = "too many attemps to fetch jwks keys"
	ErrBackendNameNotFound                             StandardError = "backend name is required but missing for %q instance in %q context"
	ErrNoBackendsFound                                 StandardError = "no backends found for %q instance in %q context"
	ErrDuplicateBackendName                            StandardError = "backend name %q is duplicate for %q instance in %q context"
	ErrBackendConfigurationFailed                      StandardError = "backend configuration for %q instance in %q context failed: %v"
	ErrBackendValidationFailed                         StandardError = "backend validation for %q instance in %q context failed: %v"

	// OAuth 2.0 backend errors.
	ErrBackendOAuthAccessTokenNotFound               StandardError = "OAuth 2.0 %s not found"
	ErrBackendOAuthAccessTokenSignMethodNotSupported StandardError = "OAuth 2.0 %s signed with unsupported algorithm: %v"
	ErrBackendOAuthAccessTokenKeyIDNotFound          StandardError = "OAuth 2.0 kid not found in %s"
	ErrBackendOAuthAccessTokenKeyIDNotRegistered     StandardError = "OAuth 2.0 %s has unregisted key id %v"
	ErrBackendOAuthParseToken                        StandardError = "OAuth 2.0 failed to parse %s: %v"
	ErrBackendOAuthInvalidToken                      StandardError = "OAuth 2.0 %s is invalid: %v"
	ErrBackendOAuthNonceValidationFailed             StandardError = "OAuth 2.0 %s nonce claim validation failed: %v"
	ErrBackendOAuthEmailNotFound                     StandardError = "OAuth 2.0 %s email claim not found"
	ErrBackendOAuthUserGroupFilterInvalid            StandardError = "user group filter %q erred: %v"
	ErrBackendOAuthUserOrgFilterInvalid              StandardError = "user org filter %q erred: %v"

	// Local backend errors.
	ErrBackendLocalConfigurePathEmpty    StandardError = "backend configuration has empty database path"
	ErrBackendLocalConfigurePathMismatch StandardError = "backend configuration database path does not match to an existing path in the same realm: %v %v"

	// LDAP backend errors.
	ErrBackendLdapAuthenticateInvalidUserEmail StandardError = "LDAP authentication request contains invalid user email"
	ErrBackendLdapAuthenticateInvalidUsername  StandardError = "LDAP authentication request contains invalid username"
	ErrBackendLdapAuthenticateInvalidPassword  StandardError = "LDAP authentication request contains invalid password"
	ErrBackendLdapAuthFailed                   StandardError = "LDAP authentication failed: %v"

	// Generic Errors.
	ErrBackendRequest   StandardError = "%s failed: %v"
	ErrBasicAuthFailed  StandardError = "basic authentication failed"
	ErrAPIKeyAuthFailed StandardError = "api key authentication failed"

	// Config Errors.
	ErrBackendConfigureEmptyConfig       StandardError = "backend configuration is empty"
	ErrBackendConfigureInvalidMethod     StandardError = "backend configuration is invalid: %s %s"
	ErrBackendConfigureMultipleMethods   StandardError = "backend configuration contains multiple methods: %v"
	ErrBackendConfigureLoggerNotFound    StandardError = "backend configuration has no logger"
	ErrBackendInvalidProvider            StandardError = "backend configuration has invalid provider: %s"
	ErrBackendConfigureNameEmpty         StandardError = "backend configuration has empty name"
	ErrBackendConfigureMethodEmpty       StandardError = "backend configuration has empty authentication method"
	ErrBackendConfigureRealmEmpty        StandardError = "backend configuration has empty realm"
	ErrBackendNewConfig                  StandardError = "backend config %v error: %v"
	ErrBackendNewConfigInvalidAuthMethod StandardError = "backend config %v has invalid auth method"
	ErrBackendConfigureInvalidBaseURL    StandardError = "backend config %q has invalid base auth url %q: %v"

	// Authentication Errors.
	ErrBackendLocalAuthFailed StandardError = "local backed authentication failed: %v"
)
