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
	"github.com/greenpau/go-identity/pkg/requests"
	"net/http"
	"net/url"
)

func (p *Authenticator) deleteAuthCookies(w http.ResponseWriter) {
	for tokenName := range p.validator.GetAuthCookies() {
		w.Header().Add("Set-Cookie", p.cookie.GetDeleteCookie(tokenName))
	}
}

func (p *Authenticator) handleHTTPLogout(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	p.disableClientCache(w)
	p.injectRedirectURL(ctx, w, r, rr)
	for tokenName := range p.validator.GetAuthCookies() {
		w.Header().Add("Set-Cookie", p.cookie.GetDeleteCookie(tokenName))
	}
	w.Header().Add("Set-Cookie", p.cookie.GetDeleteCookie(p.cookie.Referer))
	w.Header().Add("Set-Cookie", p.cookie.GetDeleteCookie(p.cookie.SessionID))
	return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
}

func (p *Authenticator) handleHTTPLogoutWithLocalRedirect(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	var refererExists bool
	p.disableClientCache(w)
	p.injectRedirectURL(ctx, w, r, rr)
	for tokenName := range p.validator.GetAuthCookies() {
		w.Header().Add("Set-Cookie", p.cookie.GetDeleteCookie(tokenName))
	}
	if rr.Response.RedirectURL == "" {
		w.Header().Add("Set-Cookie", p.cookie.GetDeleteCookie(p.cookie.Referer))
	}
	w.Header().Add("Set-Cookie", p.cookie.GetDeleteCookie(p.cookie.SessionID))
	// The redirect_url query parameter exists.
	if rr.Response.RedirectURL != "" {
		return p.handleHTTPRedirect(ctx, w, r, rr, "/login?redirect_url="+rr.Response.RedirectURL)
	}
	// Find whether the redirect cookie exists. If so, do not inject redirect URL.
	if cookie, err := r.Cookie(p.cookie.Referer); err == nil {
		v, err := url.Parse(cookie.Value)
		if err == nil && v.String() != "" {
			refererExists = true
		}
	}
	if !refererExists {
		w.Header().Add("Set-Cookie", p.cookie.GetDeleteCookie(p.cookie.Referer))
		return p.handleHTTPRedirect(ctx, w, r, rr, "/login?redirect_url="+r.RequestURI)
	}
	return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
}
