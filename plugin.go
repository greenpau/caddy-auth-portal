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

package portal

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/greenpau/caddy-auth-portal/pkg/core"
	"github.com/satori/go.uuid"
)

func init() {
	caddy.RegisterModule(AuthMiddleware{})
}

// AuthMiddleware implements Form-Based, Basic, Local, LDAP,
// OpenID Connect, OAuth 2.0, SAML Authentication.
type AuthMiddleware struct {
	Portal *core.AuthPortal `json:"portal,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (AuthMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.auth_portal",
		New: func() caddy.Module { return new(AuthMiddleware) },
	}
}

// Provision provisions authentication portal provider
func (m *AuthMiddleware) Provision(ctx caddy.Context) error {
	opts := make(map[string]interface{})
	opts["logger"] = ctx.Logger(m)
	return m.Portal.Configure(opts)
}

// Validate implements caddy.Validator.
func (m *AuthMiddleware) Validate() error {
	return nil
}

// ServeHTTP authorizes access based on the presense and content of JWT token.
func (m AuthMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	reqID := GetRequestID(r)
	opts := make(map[string]interface{})
	opts["request_id"] = reqID
	return m.Portal.ServeHTTP(w, r, opts)
}

// GetRequestID returns request ID.
func GetRequestID(r *http.Request) string {
	rawRequestID := caddyhttp.GetVar(r.Context(), "request_id")
	if rawRequestID == nil {
		requestID := uuid.NewV4().String()
		caddyhttp.SetVar(r.Context(), "request_id", requestID)
		return requestID
	}
	return rawRequestID.(string)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*AuthMiddleware)(nil)
	_ caddy.Validator             = (*AuthMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*AuthMiddleware)(nil)
)
