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

package authn

import (
	"context"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"github.com/greenpau/go-identity/pkg/requests"
	"net/http"
)

// ServeHTTP is a gateway for the authentication portal.
func (p *Authenticator) ServeHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	if rr.ID == "" {
		rr.ID = utils.GetRequestID(r)
	}
	rr.Logger = p.logger
	rr.Upstream.Request = r
	rr.Upstream.ContentType = utils.GetContentType(r)
	rr.Response.Authenticated = false
	if p.UI.Title != "" {
		rr.Response.Title = p.UI.Title
	}
	rr.Response.RedirectTokenName = p.cookie.Referer
	switch rr.Upstream.ContentType {
	case "application/json":
		return p.handleJSON(ctx, w, r, rr)
	}
	return p.handleHTTP(ctx, w, r, rr)
}
