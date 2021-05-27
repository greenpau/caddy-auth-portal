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
	"fmt"
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
	"github.com/greenpau/caddy-auth-portal/pkg/backends"
	"github.com/greenpau/caddy-auth-portal/pkg/enums/operator"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"github.com/greenpau/go-identity/pkg/requests"
	"go.uber.org/zap"
	"net/http"
	"net/url"
	"path"
	"time"
)

func (p *Authenticator) handleHTTPLogin(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, usr *user.User) error {
	p.injectRedirectURL(ctx, w, r, rr)
	if usr != nil {
		return p.handleHTTPRedirect(ctx, w, r, rr, "/portal")
	}
	if r.Method != "POST" {
		return p.handleHTTPLoginScreen(ctx, w, r, rr)
	}
	return p.handleHTTPLoginRequest(ctx, w, r, rr)
}

func (p *Authenticator) handleHTTPLoginScreen(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	resp := p.ui.GetArgs()
	resp.BaseURL(rr.Upstream.BasePath)
	if p.UI.Title == "" {
		resp.Title = "Sign In"
	} else {
		resp.Title = p.UI.Title
	}
	resp.Data["authenticated"] = rr.Response.Authenticated
	resp.Data["login_options"] = p.loginOptions

	content, err := p.ui.Render("login", resp)
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}
	return p.handleHTTPRenderHTML(ctx, w, http.StatusOK, content.Bytes())
}

func (p *Authenticator) getBackendByRealm(realm string) *backends.Backend {
	for _, backend := range p.backends {
		if backend.GetRealm() == realm {
			return backend
		}
	}
	return nil
}

func (p *Authenticator) handleHTTPLoginRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	p.disableClientCache(w)
	if r.Method != "POST" {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusUnauthorized)
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	credentials, err := utils.ParseCredentials(r)
	if err != nil {
		return p.handleHTTPErrorWithLog(ctx, w, r, rr, http.StatusUnauthorized, err.Error())
	}
	code, err := p.authenticateLoginRequest(ctx, w, r, rr, credentials)
	if err != nil {
		return p.handleHTTPErrorWithLog(ctx, w, r, rr, code, err.Error())
	}
	w.WriteHeader(code)
	return nil
}

func (p *Authenticator) authenticateLoginRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, credentials map[string]string) (int, error) {
	rr.User.Username = credentials["username"]
	rr.User.Password = credentials["password"]
	backend := p.getBackendByRealm(credentials["realm"])
	if backend == nil {
		return http.StatusBadRequest, fmt.Errorf("no matching realm found")
	}
	rr.Upstream.Method = backend.GetMethod()
	rr.Upstream.Realm = backend.GetRealm()
	err := backend.Request(operator.Authenticate, rr)
	if err != nil {
		return http.StatusUnauthorized, err
	}

	switch m := rr.Response.Payload.(type) {
	case map[string]interface{}:
		m["jti"] = rr.Upstream.SessionID
		m["exp"] = time.Now().Add(time.Duration(p.keystore.GetTokenLifetime(nil, nil)) * time.Second).UTC().Unix()
		m["iat"] = time.Now().UTC().Unix()
		m["nbf"] = time.Now().Add(time.Duration(60) * time.Second * -1).UTC().Unix()
		m["origin"] = backend.GetRealm()
		m["iss"] = utils.GetCurrentURL(r)
		m["addr"] = utils.GetSourceAddress(r)
		usr, err := user.NewUser(m)
		if err != nil {
			return http.StatusUnauthorized, err
		}
		if err := p.keystore.SignToken(nil, nil, usr); err != nil {
			return http.StatusInternalServerError, err
		}
		usr.Authenticator.Name = backend.GetName()
		usr.Authenticator.Realm = backend.GetRealm()
		usr.Authenticator.Method = backend.GetMethod()
		p.logger.Info(
			"Successful login",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Any("backend", usr.Authenticator),
			zap.Any("user", m),
		)
		p.sessions.Add(rr.Upstream.SessionID, usr)
		w.Header().Set("Authorization", "Bearer "+usr.Token)
		w.Header().Set("Set-Cookie", p.cookie.GetCookie(usr.TokenName, usr.Token))

		var redirectLocation string
		// Determine whether redirect cookie is present and reditect to the page that
		// forwarded a user to the authentication portal.
		if cookie, err := r.Cookie(p.cookie.Referer); err == nil {
			if redirectURL, err := url.Parse(cookie.Value); err == nil {
				redirectLocation = redirectURL.String()
				p.logger.Debug(
					"Detected cookie-based redirect",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("redirect_url", redirectLocation),
				)
				w.Header().Add("Set-Cookie", p.cookie.GetDeleteCookie(p.cookie.Referer))
			}
		}
		if redirectLocation == "" {
			// Redirect authenticated user to portal page when no redirect cookie found.
			redirectLocation = rr.Upstream.BaseURL + path.Join(rr.Upstream.BasePath, "/portal")
		}
		w.Header().Set("Location", redirectLocation)
		return http.StatusSeeOther, nil
	}
	return http.StatusBadRequest, fmt.Errorf("unsupported backend response payload %T", rr.Response.Payload)
}
