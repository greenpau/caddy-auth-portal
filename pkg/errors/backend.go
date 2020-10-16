package errors

// Backend errors.
const (
	ErrBackendOauthAuthorizationStateNotFound StandardError = "OAuth 2.0 authorization state not found"
	ErrBackendRealmNotFound                   StandardError = "no realm found for provider %s"
	ErrBackendClientIDNotFound                StandardError = "no client_id found for provider %s"
	ErrBackendClientSecretNotFound            StandardError = "no client_secret found for provider %s"
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
)
