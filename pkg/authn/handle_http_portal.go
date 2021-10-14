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
	"github.com/greenpau/caddy-authorize/pkg/user"
	"github.com/greenpau/go-identity/pkg/requests"
	"go.uber.org/zap"
	"net/http"
	"net/url"
)

func (p *Authenticator) handleHTTPPortal(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, parsedUser *user.User) error {
	p.disableClientCache(w)
	p.injectRedirectURL(ctx, w, r, rr)
	if parsedUser == nil {
		return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
	}
	usr, err := p.sessions.Get(parsedUser.Claims.ID)
	if err != nil {
		p.deleteAuthCookies(w)
		p.logger.Debug(
			"User session not found, redirect to login",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Any("user", parsedUser.Claims),
		)
		return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
	}
	return p.handleHTTPPortalScreen(ctx, w, r, rr, usr)
}

func (p *Authenticator) handleHTTPPortalScreen(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, usr *user.User) error {
	if cookie, err := r.Cookie(p.cookie.Referer); err == nil {
		redirectURL, err := url.Parse(cookie.Value)
		if err == nil {
			p.logger.Debug(
				"Cookie-based redirect",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("redirect_url", redirectURL.String()),
			)
			w.Header().Set("Location", redirectURL.String())
			w.Header().Add("Set-Cookie", p.cookie.GetDeleteCookie(p.cookie.Referer))
			w.WriteHeader(http.StatusSeeOther)
			return nil
		}
	}
	resp := p.ui.GetArgs()
	resp.BaseURL(rr.Upstream.BasePath)
	resp.Title = "Welcome"
	if len(usr.FrontendLinks) > 0 {
		// Add additional frontend links.
		resp.AddFrontendLinks(usr.FrontendLinks)
	}
	content, err := p.ui.Render("portal", resp)
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}
	return p.handleHTTPRenderHTML(ctx, w, http.StatusOK, content.Bytes())
}
