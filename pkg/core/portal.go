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

package core

import (
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	jwtclaims "github.com/greenpau/caddy-auth-jwt/pkg/claims"
	jwtconfig "github.com/greenpau/caddy-auth-jwt/pkg/config"
	jwtvalidator "github.com/greenpau/caddy-auth-jwt/pkg/validator"

	"github.com/greenpau/caddy-auth-portal/pkg/backends"
	"github.com/greenpau/caddy-auth-portal/pkg/cache"
	"github.com/greenpau/caddy-auth-portal/pkg/cookies"
	"github.com/greenpau/caddy-auth-portal/pkg/handlers"
	"github.com/greenpau/caddy-auth-portal/pkg/registration"
	"github.com/greenpau/caddy-auth-portal/pkg/ui"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"github.com/greenpau/go-identity"
	uuid "github.com/satori/go.uuid"
	"go.uber.org/zap"
)

const (
	redirectToToken = "AUTH_PORTAL_REDIRECT_URL"
)

// PortalManager is the global authentication provider pool.
// It provides access to all instances of authentication portal plugin.
var PortalManager *AuthPortalManager

var sessionCache *cache.SessionCache
var sandboxCache *cache.SandboxCache

func init() {
	sessionCache, _ = cache.NewSessionCache(nil)
	sandboxCache, _ = cache.NewSandboxCache(nil)

	PortalManager = &AuthPortalManager{}
}

// AuthPortal implements Form-Based, Basic, Local, LDAP,
// OpenID Connect, OAuth 2.0, SAML Authentication.
type AuthPortal struct {
	Name                     string                       `json:"-"`
	Provisioned              bool                         `json:"-"`
	ProvisionFailed          bool                         `json:"-"`
	PrimaryInstance          bool                         `json:"primary,omitempty"`
	Context                  string                       `json:"context,omitempty"`
	AuthURLPath              string                       `json:"auth_url_path,omitempty"`
	UserInterface            *ui.UserInterfaceParameters  `json:"ui,omitempty"`
	UserRegistration         *registration.Registration   `json:"registration,omitempty"`
	UserRegistrationDatabase *identity.Database           `json:"-"`
	Cookies                  *cookies.Cookies             `json:"cookies,omitempty"`
	Backends                 []backends.Backend           `json:"backends,omitempty"`
	TokenProvider            *jwtconfig.CommonTokenConfig `json:"jwt,omitempty"`
	EnableSourceIPTracking   bool                         `json:"source_ip_tracking,omitempty"`
	RequireMFA               bool                         `json:"require_mfa,omitempty"`
	TokenValidator           *jwtvalidator.TokenValidator `json:"-"`
	logger                   *zap.Logger
	uiFactory                *ui.UserInterfaceFactory
	startedAt                time.Time
	loginOptions             map[string]interface{}
}

// Configure configures the instance of authentication portal.
func (p *AuthPortal) Configure(upstreamOptions map[string]interface{}) error {
	if _, exists := upstreamOptions["logger"]; !exists {
		return fmt.Errorf("configuration requires valid logger")
	}
	p.logger = upstreamOptions["logger"].(*zap.Logger)
	p.startedAt = time.Now().UTC()

	if sandboxCache == nil {
		return fmt.Errorf(
			"authentication provider registration error, instance %s, error: %s",
			p.Name, "sandbox cache is nil",
		)
	}

	if err := PortalManager.Register(p); err != nil {
		return fmt.Errorf(
			"authentication provider registration error, instance %s, error: %s",
			p.Name, err,
		)
	}

	if !p.PrimaryInstance {
		if err := PortalManager.Provision(p.Name); err != nil {
			return fmt.Errorf(
				"authentication provider provisioning error, instance %s, error: %s",
				p.Name, err,
			)
		}
	}
	p.logger.Info(
		"provisioned plugin instance",
		zap.String("instance_name", p.Name),
		zap.Time("started_at", p.startedAt),
	)
	return nil
}

// ServeHTTP authorizes access based on the presense and content of JWT token.
func (p *AuthPortal) ServeHTTP(w http.ResponseWriter, r *http.Request, upstreamOptions map[string]interface{}) error {
	var reqID string
	if _, exists := upstreamOptions["request_id"]; exists {
		reqID = upstreamOptions["request_id"].(string)
	} else {
		reqID = GetRequestID(r)
	}
	log := p.logger
	opts := make(map[string]interface{})
	opts["request_id"] = reqID
	opts["content_type"] = utils.GetContentType(r)
	opts["authenticated"] = false
	opts["auth_backend_found"] = false
	opts["auth_credentials_found"] = false
	opts["logger"] = log
	opts["auth_url_path"] = p.AuthURLPath
	opts["ui"] = p.uiFactory
	opts["cookies"] = p.Cookies
	opts["cookie_names"] = []string{redirectToToken, p.TokenProvider.TokenName}
	opts["token_provider"] = p.TokenProvider
	if p.UserInterface.Title != "" {
		opts["ui_title"] = p.UserInterface.Title
	}
	opts["redirect_token_name"] = redirectToToken

	urlPath := strings.TrimPrefix(r.URL.Path, p.AuthURLPath)
	urlPath = strings.TrimPrefix(urlPath, "/")

	// Find JWT tokens, if any, and validate them.
	if claims, authOK, err := p.TokenValidator.Authorize(r, nil); authOK {
		opts["authenticated"] = true
		opts["user_claims"] = claims
	} else {
		if err != nil {
			switch err.Error() {
			case "[Token is expired]":
				return handlers.ServeSessionLoginRedirect(w, r, opts)
			case "no token found":
			default:
				log.Warn("Authorization failed",
					zap.String("request_id", opts["request_id"].(string)),
					zap.Any("error", err.Error()),
					zap.String("src_ip_address", utils.GetSourceAddress(r)),
				)
			}
		}
	}

	// Handle requests based on query parameters.
	if r.Method == "GET" {
		q := r.URL.Query()
		foundQueryOptions := false
		if redirectURL, exists := q["redirect_url"]; exists {
			if !strings.HasSuffix(redirectURL[0], ".css") && !strings.HasSuffix(redirectURL[0], ".js") {
				w.Header().Set("Set-Cookie", p.Cookies.GetCookie(redirectToToken, redirectURL[0]))
				foundQueryOptions = true
			}
		}
		if !strings.HasPrefix(urlPath, "saml") && !strings.HasPrefix(urlPath, "x509") && !strings.HasPrefix(urlPath, "oauth2") {
			if foundQueryOptions {
				w.Header().Set("Location", p.AuthURLPath)
				w.WriteHeader(302)
				return nil
			}
		}
	}

	// Perform request routing
	switch {
	case strings.HasPrefix(urlPath, "register"):
		if p.UserRegistration.Disabled {
			opts["flow"] = "unsupported_feature"
			return handlers.ServeGeneric(w, r, opts)
		}
		if p.UserRegistration.Dropbox == "" {
			opts["flow"] = "unsupported_feature"
			return handlers.ServeGeneric(w, r, opts)
		}
		opts["flow"] = "register"
		opts["registration"] = p.UserRegistration
		opts["registration_db"] = p.UserRegistrationDatabase
		return handlers.ServeRegister(w, r, opts)
	case strings.HasPrefix(urlPath, "recover"),
		strings.HasPrefix(urlPath, "forgot"):
		// opts["flow"] = "recover"
		opts["flow"] = "unsupported_feature"
		return handlers.ServeGeneric(w, r, opts)
	case strings.HasPrefix(urlPath, "logout"),
		strings.HasPrefix(urlPath, "logoff"):
		opts["flow"] = "logout"
		return handlers.ServeSessionLogoff(w, r, opts)
	case strings.HasPrefix(urlPath, "assets"):
		opts["url_path"] = urlPath
		opts["flow"] = "assets"
		return handlers.ServeStaticAssets(w, r, opts)
	case strings.HasPrefix(urlPath, "whoami"):
		opts["flow"] = "whoami"
		return handlers.ServeWhoami(w, r, opts)
	case strings.HasPrefix(urlPath, "settings"):
		opts["flow"] = "settings"
		if opts["authenticated"].(bool) {
			claims := opts["user_claims"].(*jwtclaims.UserClaims)
			if sessionData, err := sessionCache.Get(claims.ID); err != nil {
				log.Warn(
					"Failed to get session id to claims mapping",
					zap.String("request_id", reqID),
					zap.String("error", err.Error()),
				)
			} else {
				sessionDataOpts := make(map[string]string)
				for _, k := range []string{"backend_method", "backend_name", "backend_realm"} {
					if _, exists := sessionData[k]; !exists {
						sessionDataOpts = nil
						break
					}
					sessionDataOpts[k] = sessionData[k].(string)
				}
				if len(sessionDataOpts) > 0 {
					for _, backend := range p.Backends {
						if backend.GetRealm() != sessionDataOpts["backend_realm"] {
							continue
						}
						if backend.GetName() != sessionDataOpts["backend_name"] {
							continue
						}
						if backend.GetMethod() != sessionDataOpts["backend_method"] {
							continue
						}
						opts["backend"] = &backend
						break
					}
				}
			}
			if _, exists := opts["backend"]; !exists {
				opts["flow"] = "logout"
				opts["redirect_url"] = r.RequestURI
				return handlers.ServeSessionLogoff(w, r, opts)
			}
		}
		return handlers.ServeSettings(w, r, opts)
	case strings.HasPrefix(urlPath, "portal"):
		opts["flow"] = "portal"
		return handlers.ServePortal(w, r, opts)
	case strings.HasPrefix(urlPath, "sandbox"):
		var sandboxView string
		var reqSandboxView string
		var sandboxAction string
		var sessionID string
		var err error
		var sessionData map[string]interface{}
		var mfaConfig map[string]bool
		var claims *jwtclaims.UserClaims
		var sandboxAuthFailed bool

		// TODO: remove start
		// opts["sandbox_id"] = "78t0rlcs7e03b1ga64kuz09igvfa0u3vn5r8q3bl6hwzroptjmrelabmwf1uko0w7y91bm6"
		// opts["sandbox_view"] = "mfa_mixed_register"
		// opts["sandbox_view"] = "mfa_mixed_auth"
		// opts["sandbox_view"] = "mfa_app_auth"
		// opts["sandbox_view"] = "mfa_u2f_auth"
		// opts["sandbox_view"] = "mfa_app_register"
		// opts["sandbox_view"] = "mfa_u2f_register"

		// opts["sandbox_action"] = "auth"
		// opts["sandbox_action"] = "register"
		// return handlers.ServeSandbox(w, r, opts)

		// TODO: remove end

		opts["flow"] = "sandbox"
		urlPathParts := strings.Split(urlPath, "/")
		urlPathPartsLength := len(urlPathParts)
		if urlPathPartsLength < 2 || urlPathPartsLength > 5 {
			// Malformed URI path
			opts["status_code"] = 401
			opts["flow"] = "auth_failed"
			opts["authenticated"] = false
			log.Warn(
				"Malformed sandbox authentication request",
				zap.String("request_id", reqID),
				zap.String("error", "malformed uri path"),
				zap.Int("uri_parts", urlPathPartsLength),
			)
			return handlers.ServeGeneric(w, r, opts)
		}

		sandboxID := urlPathParts[1]

		// determine authentication or registration flow
		switch urlPathPartsLength {
		case 2:
			reqSandboxView = "mfa_tbd"
		case 3:
			switch urlPathParts[2] {
			case "auth":
				// User gets presented with the choice of both App and U2F authenticators
				// i.e. /sandbox/:id/auth
				reqSandboxView = "mfa_mixed_auth"
			case "register":
				// User gets prompted to register with the choice of both App and U2F authenticators
				// i.e. /sandbox/:id/register
				reqSandboxView = "mfa_mixed_register"
			default:
				sandboxAuthFailed = true
			}
		case 4, 5:
			switch urlPathParts[3] {
			case "auth":
				switch urlPathParts[2] {
				case "app":
					// User gets presented with app authenticator authentication screen
					// i.e. /sandbox/:id/app/auth
					reqSandboxView = "mfa_app_auth"
				case "u2f":
					// User gets presented with U2F authenticator authentication screen
					// i.e. /sandbox/:id/u2f/auth
					reqSandboxView = "mfa_u2f_auth"
				default:
					sandboxAuthFailed = true
				}
			case "register":
				switch urlPathParts[2] {
				case "app":
					// User gets presented with app authenticator registration screen
					// i.e. /sandbox/:id/app/register
					reqSandboxView = "mfa_app_register"
				case "u2f":
					// User gets presented with U2F authenticator registration screen
					// i.e. /sandbox/:id/u2f/register
					reqSandboxView = "mfa_u2f_register"
				default:
					sandboxAuthFailed = true
				}
			default:
				sandboxAuthFailed = true
			}
		default:
			sandboxAuthFailed = true
		}

		// handle check for success/error messages
		if !sandboxAuthFailed && (urlPathPartsLength == 5) {
			switch urlPathParts[4] {
			case "success", "error":
				reqSandboxView = fmt.Sprintf("%s_%s", reqSandboxView, urlPathParts[4])
			default:
				sandboxAuthFailed = true
			}
		}

		if sandboxAuthFailed {
			// Malformed URI path
			opts["status_code"] = 401
			opts["flow"] = "auth_failed"
			opts["authenticated"] = false
			log.Warn(
				"Malformed sandbox authentication request",
				zap.String("request_id", reqID),
				zap.String("error", "malformed uri path"),
			)
			return handlers.ServeGeneric(w, r, opts)
		}

		sessionID, err = sandboxCache.Get(sandboxID)
		if err != nil {
			// Sandbox cache entry with session ID to claims ID
			// mapping not found
			opts["status_code"] = 401
			opts["flow"] = "auth_failed"
			opts["authenticated"] = false
			log.Warn(
				"Failed to get sandbox id to claims mapping",
				zap.String("request_id", reqID),
				zap.String("error", err.Error()),
			)
			return handlers.ServeGeneric(w, r, opts)
		}

		sessionData, err = sessionCache.Get(sessionID)
		if err != nil {
			// Session cache entry with session ID and data not found
			opts["status_code"] = 401
			opts["flow"] = "auth_failed"
			opts["authenticated"] = false
			log.Warn(
				"Failed to get session id to claims mapping",
				zap.String("request_id", reqID),
				zap.String("error", err.Error()),
			)
			return handlers.ServeGeneric(w, r, opts)
		}

		rawClaims, exists := sessionData["claims"]
		if !exists {
			// Session cache entry did not have claims
			opts["status_code"] = 401
			opts["flow"] = "auth_failed"
			opts["authenticated"] = false
			log.Warn(
				"Failed to get session id to claims mapping",
				zap.String("request_id", reqID),
				zap.String("error", "claims not found"),
			)
			return handlers.ServeGeneric(w, r, opts)
		}
		claims = rawClaims.(*jwtclaims.UserClaims)

		if claims.Metadata == nil {
			// Session cache entry did not have metadata for user claims
			opts["status_code"] = 401
			opts["flow"] = "auth_failed"
			opts["authenticated"] = false
			log.Warn(
				"Failed to get session id to claims mapping",
				zap.String("request_id", reqID),
				zap.String("error", "claims metadata is nil"),
			)
			return handlers.ServeGeneric(w, r, opts)
		}

		// Check which views are available for a particular user.
		mfaConfig = make(map[string]bool)
		for _, k := range []string{"mfa_configured", "mfa_app_configured", "mfa_u2f_configured"} {
			if v, exists := claims.Metadata[k]; exists {
				switch v.(type) {
				case bool:
				default:
					log.Warn(
						"Failed to get session id to claims mapping",
						zap.String("request_id", reqID),
						zap.String("error", fmt.Sprintf("user claims metadata %s field is not bool", k)),
					)
					sandboxAuthFailed = true
				}
				if sandboxAuthFailed {
					break
				}
				mfaConfig[k] = v.(bool)
			} else {
				log.Warn(
					"Failed to get session id to claims mapping",
					zap.String("request_id", reqID),
					zap.String("error", fmt.Sprintf("user claims metadata %s field not found", k)),
				)
				sandboxAuthFailed = true
				break
			}
		}

		if sandboxAuthFailed {
			opts["status_code"] = 401
			opts["flow"] = "auth_failed"
			opts["authenticated"] = false
			return handlers.ServeGeneric(w, r, opts)
		}

		// Check whether the requested sandbox view is supported by MFA configuration metadata
		if reqSandboxView == "mfa_tbd" {
			if mfaConfig["mfa_app_configured"] {
				// redirect from tbd to mixed auth
				w.Header().Set("Location", path.Join(p.AuthURLPath, "sandbox", sandboxID, "auth"))
				w.WriteHeader(302)
				return nil
			}
			// redirect from tbd to mixed register
			w.Header().Set("Location", path.Join(p.AuthURLPath, "sandbox", sandboxID, "register"))
			w.WriteHeader(302)
			return nil
		}

		sandboxView = reqSandboxView
		switch reqSandboxView {
		case "mfa_app_auth":
			if !mfaConfig["mfa_app_configured"] {
				sandboxAuthFailed = true
				break
			}
			if !mfaConfig["mfa_app_configured"] {
				sandboxAuthFailed = true
				break
			}
			sandboxAction = "auth"
		case "mfa_u2f_auth":
			if !mfaConfig["mfa_u2f_configured"] {
				sandboxAuthFailed = true
				break
			}
			if !mfaConfig["mfa_u2f_configured"] {
				sandboxAuthFailed = true
				break
			}
			sandboxAction = "auth"
		case "mfa_mixed_auth":
			if !mfaConfig["mfa_configured"] {
				sandboxAuthFailed = true
				break
			}
			if mfaConfig["mfa_app_configured"] && mfaConfig["mfa_u2f_configured"] {
				sandboxAction = "auth"
				break
			}
			if mfaConfig["mfa_app_configured"] {
				// redirect from mixed auth to app auth
				w.Header().Set("Location", path.Join(p.AuthURLPath, "sandbox", sandboxID, "app/auth"))
				w.WriteHeader(302)
				return nil
			}
			// redirect from mixed auth to u2f auth
			w.Header().Set("Location", path.Join(p.AuthURLPath, "sandbox", sandboxID, "u2f/auth"))
			w.WriteHeader(302)
			return nil
		case "mfa_app_register", "mfa_u2f_register", "mfa_mixed_register":
			if mfaConfig["mfa_configured"] {
				sandboxAuthFailed = true
				break
			}
			sandboxAction = "register"
		default:
			if !strings.HasSuffix(reqSandboxView, "_success") && !strings.HasSuffix(reqSandboxView, "_error") {
				sandboxAuthFailed = true
				log.Warn(
					"Failed to determine appropriate view",
					zap.String("request_id", reqID),
					zap.String("error", fmt.Sprintf("unsupported sandbox view %s", reqSandboxView)),
				)
			}
		}

		if sandboxAuthFailed {
			opts["status_code"] = 401
			opts["flow"] = "auth_failed"
			opts["authenticated"] = false
			return handlers.ServeGeneric(w, r, opts)
		}

		if r.Method == "POST" {
			// set the sandbox entries to used
			switch sandboxView {
			case "mfa_app_auth", "mfa_u2f_auth", "mfa_app_register", "mfa_u2f_register":
				_, err = sandboxCache.Use(sandboxID)
				if err != nil {
					log.Warn(
						"Failed to get sandbox id to claims mapping",
						zap.String("request_id", reqID),
						zap.String("error", err.Error()),
						zap.String("sandbox_id", sandboxID),
						zap.String("sandbox_view", sandboxView),
					)
					opts["status_code"] = 401
					opts["flow"] = "auth_failed"
					opts["authenticated"] = false
					return handlers.ServeGeneric(w, r, opts)
				}
			}
			// handle registration and authentication submissions
			switch sandboxView {
			case "mfa_app_auth":
				w.Header().Set("Location", path.Join(p.AuthURLPath, "sandbox", sandboxID, "app/auth/error"))
				w.WriteHeader(302)
				return nil
			case "mfa_u2f_auth":
				w.Header().Set("Location", path.Join(p.AuthURLPath, "sandbox", sandboxID, "u2f/auth/error"))
				w.WriteHeader(302)
				return nil
			case "mfa_app_register":
				w.Header().Set("Location", path.Join(p.AuthURLPath, "sandbox", sandboxID, "app/register/error"))
				w.WriteHeader(302)
				return nil
			case "mfa_u2f_register":
				w.Header().Set("Location", path.Join(p.AuthURLPath, "sandbox", sandboxID, "u2f/register/error"))
				w.WriteHeader(302)
				return nil
			default:
				log.Warn(
					"Malformed request",
					zap.String("request_id", reqID),
					zap.String("error", "unsupported POST endpoint"),
					zap.String("sandbox_id", sandboxID),
					zap.String("sandbox_view", sandboxView),
				)
				opts["status_code"] = 401
				opts["flow"] = "auth_failed"
				opts["authenticated"] = false
				return handlers.ServeGeneric(w, r, opts)
			}

			// opts["sandbox_id"] = sandboxID
			// opts["sandbox_view"] = sandboxView
			// opts["sandbox_action"] = sandboxAction
		}

		opts["sandbox_id"] = sandboxID
		opts["sandbox_view"] = sandboxView
		opts["sandbox_action"] = sandboxAction

		if r.Method == "GET" {
			// set the sandbox entries to landed
			switch sandboxView {
			case "mfa_app_auth", "mfa_u2f_auth", "mfa_app_register", "mfa_u2f_register":
				_, err = sandboxCache.Land(sandboxID)
				if err != nil {
					log.Warn(
						"Failed to get sandbox id to claims mapping",
						zap.String("request_id", reqID),
						zap.String("error", err.Error()),
						zap.String("sandbox_id", sandboxID),
						zap.String("sandbox_view", sandboxView),
					)
					opts["status_code"] = 401
					opts["flow"] = "auth_failed"
					opts["authenticated"] = false
					return handlers.ServeGeneric(w, r, opts)
				}
			}
		}

		return handlers.ServeSandbox(w, r, opts)
	case strings.HasPrefix(urlPath, "saml"), strings.HasPrefix(urlPath, "x509"), strings.HasPrefix(urlPath, "oauth2"):
		urlPathParts := strings.Split(urlPath, "/")
		if len(urlPathParts) < 2 {
			opts["status_code"] = 400
			opts["flow"] = "malformed_backend"
			opts["authenticated"] = false
			return handlers.ServeGeneric(w, r, opts)
		}
		reqBackendMethod := urlPathParts[0]
		reqBackendRealm := urlPathParts[1]
		opts["flow"] = reqBackendMethod
		for _, backend := range p.Backends {
			if backend.GetRealm() != reqBackendRealm {
				continue
			}
			if backend.GetMethod() != reqBackendMethod {
				continue
			}
			opts["request"] = r
			opts["request_path"] = path.Join(p.AuthURLPath, reqBackendMethod, reqBackendRealm)
			resp, err := backend.Authenticate(opts)
			if err != nil {
				opts["flow"] = "auth_failed"
				opts["authenticated"] = false
				opts["message"] = "Authentication failed"
				opts["status_code"] = resp["code"].(int)
				log.Warn("Authentication failed",
					zap.String("request_id", reqID),
					zap.String("auth_method", reqBackendMethod),
					zap.String("auth_realm", reqBackendRealm),
					zap.String("error", err.Error()),
				)
				return handlers.ServeGeneric(w, r, opts)
			}
			if v, exists := resp["redirect_url"]; exists {
				// Redirect to external provider
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Pragma", "no-cache")
				http.Redirect(w, r, v.(string), http.StatusFound)
				return nil
			}
			if _, exists := resp["claims"]; !exists {
				opts["flow"] = "auth_failed"
				opts["authenticated"] = false
				opts["message"] = "Authentication failed"
				opts["status_code"] = resp["code"].(int)
				log.Warn("Authentication failed",
					zap.String("request_id", reqID),
					zap.String("auth_method", reqBackendMethod),
					zap.String("auth_realm", reqBackendRealm),
					zap.String("error", err.Error()),
				)
				return handlers.ServeGeneric(w, r, opts)
			}

			claims := resp["claims"].(*jwtclaims.UserClaims)
			claims.ID = reqID
			claims.Issuer = utils.GetCurrentURL(r)
			if p.EnableSourceIPTracking {
				claims.Address = utils.GetSourceAddress(r)
			}
			sessionCache.Add(claims.ID, map[string]interface{}{
				"claims":         claims,
				"backend_name":   backend.GetName(),
				"backend_realm":  backend.GetRealm(),
				"backend_method": backend.GetMethod(),
			})
			opts["authenticated"] = true
			opts["user_claims"] = claims
			opts["status_code"] = 200
			log.Debug("Authentication succeeded",
				zap.String("request_id", reqID),
				zap.String("auth_method", reqBackendMethod),
				zap.String("auth_realm", reqBackendRealm),
				zap.Any("user", claims),
			)
			return handlers.ServeLogin(w, r, opts)
		}
		opts["status_code"] = 400
		opts["flow"] = "backend_not_found"
		opts["authenticated"] = false
		return handlers.ServeGeneric(w, r, opts)
	case strings.HasPrefix(urlPath, "login"), urlPath == "":
		opts["flow"] = "login"
		opts["login_options"] = p.loginOptions
		if opts["authenticated"].(bool) {
			opts["authorized"] = true
		} else {
			// Authenticating the request
			if credentials, err := utils.ParseCredentials(r); err == nil {
				if credentials != nil {
					opts["auth_credentials_found"] = true
					for _, backend := range p.Backends {
						if backend.GetRealm() != credentials["realm"] {
							continue
						}
						opts["auth_backend_found"] = true
						opts["auth_credentials"] = credentials
						if resp, err := backend.Authenticate(opts); err != nil {
							opts["message"] = "Authentication failed"
							opts["status_code"] = resp["code"].(int)
							log.Warn("Authentication failed",
								zap.String("request_id", reqID),
								zap.String("error", err.Error()),
							)
						} else {
							claims := resp["claims"].(*jwtclaims.UserClaims)
							claims.ID = reqID
							claims.Issuer = utils.GetCurrentURL(r)
							if p.EnableSourceIPTracking {
								claims.Address = utils.GetSourceAddress(r)
							}
							sessionCache.Add(claims.ID, map[string]interface{}{
								"claims":         claims,
								"backend_name":   backend.GetName(),
								"backend_realm":  backend.GetRealm(),
								"backend_method": backend.GetMethod(),
							})
							// Check whether this authenticated request requires
							// MFA in the sandbox environment
							if claims.Metadata != nil {
								if v, exists := claims.Metadata["mfa_required"]; exists {
									if v.(bool) {
										sandboxID, err := sandboxCache.Add(claims.ID)
										if err != nil {
											opts["message"] = "Internal Server Error. Please Contact Support"
											opts["status_code"] = 500
											log.Warn(
												"Failed to add sandbox id to claims mapping",
												zap.String("request_id", reqID),
												zap.String("error", err.Error()),
											)
											return handlers.ServeLogin(w, r, opts)
										}
										w.Header().Set("Location", path.Join(p.AuthURLPath, "sandbox", sandboxID))
										w.WriteHeader(302)
										return nil
									}
								}
							}
							opts["user_claims"] = claims
							opts["authenticated"] = true
							opts["status_code"] = 200
							log.Debug("Authentication succeeded",
								zap.String("request_id", reqID),
								zap.Any("user", claims),
							)
						}
					}
					if !opts["auth_backend_found"].(bool) {
						opts["status_code"] = 500
						log.Warn("Authentication failed",
							zap.String("request_id", reqID),
							zap.String("error", "no matching auth backend found"),
						)
					}
				}
			} else {
				opts["message"] = "Authentication failed"
				opts["status_code"] = 400
				log.Warn("Authentication failed",
					zap.String("request_id", reqID),
					zap.String("error", err.Error()),
				)
			}
		}
		return handlers.ServeLogin(w, r, opts)
	default:
		opts["flow"] = "not_found"
		return handlers.ServeGeneric(w, r, opts)
	}
}

// GetRequestID returns request ID.
func GetRequestID(r *http.Request) string {
	requestID := uuid.NewV4().String()
	return requestID
}
