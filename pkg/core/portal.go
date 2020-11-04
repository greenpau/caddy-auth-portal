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
	"github.com/satori/go.uuid"
	"go.uber.org/zap"
)

const (
	redirectToToken = "AUTH_PORTAL_REDIRECT_URL"
)

// PortalManager is the global authentication provider pool.
// It provides access to all instances of authentication portal plugin.
var PortalManager *AuthPortalManager

var sessionCache *cache.SessionCache

func init() {
	sessionCache = cache.NewSessionCache()
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
				w.Header().Set("Set-Cookie", redirectToToken+"="+redirectURL[0]+";"+p.Cookies.GetAttributes())
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
			if bknd := sessionCache.Get(claims.ID); bknd != nil {
				bkndOpts := make(map[string]string)
				for _, k := range []string{"backend_method", "backend_name", "backend_realm"} {
					if _, exists := bknd[k]; !exists {
						bkndOpts = nil
						break
					}
					bkndOpts[k] = bknd[k].(string)
				}
				if len(bkndOpts) > 0 {
					for _, backend := range p.Backends {
						if backend.GetRealm() != bkndOpts["backend_realm"] {
							continue
						}
						if backend.GetName() != bkndOpts["backend_name"] {
							continue
						}
						if backend.GetMethod() != bkndOpts["backend_method"] {
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
