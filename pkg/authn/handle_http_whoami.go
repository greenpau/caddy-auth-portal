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
	"encoding/json"
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
	"github.com/greenpau/go-identity/pkg/requests"
	"net/http"
	"time"
)

func (p *Authenticator) handleHTTPWhoami(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, usr *user.User) error {
	p.disableClientCache(w)
	p.injectRedirectURL(ctx, w, r, rr)
	if usr == nil {
		if rr.Response.RedirectURL == "" {
			return p.handleHTTPRedirect(ctx, w, r, rr, "/login?redirect_url="+r.RequestURI)
		}
		return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
	}
	resp := p.ui.GetArgs()
	resp.Title = "User Identity"
	resp.BaseURL(rr.Upstream.BasePath)
	tokenMap := make(map[string]interface{})
	for k, v := range usr.AsMap() {
		tokenMap[k] = v
	}
	tokenMap["authenticated"] = true
	if usr.Claims.ExpiresAt > 0 {
		tokenMap["expires_at_utc"] = time.Unix(usr.Claims.ExpiresAt, 0).Format(time.UnixDate)
	}
	if usr.Claims.IssuedAt > 0 {
		tokenMap["issued_at_utc"] = time.Unix(usr.Claims.IssuedAt, 0).Format(time.UnixDate)
	}
	if usr.Claims.NotBefore > 0 {
		tokenMap["not_before_utc"] = time.Unix(usr.Claims.NotBefore, 0).Format(time.UnixDate)
	}
	prettyTokenMap, err := json.MarshalIndent(tokenMap, "", "  ")
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}
	resp.Data["token"] = string(prettyTokenMap)

	content, err := p.ui.Render("whoami", resp)
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}
	return p.handleHTTPRenderHTML(ctx, w, http.StatusOK, content.Bytes())
}
