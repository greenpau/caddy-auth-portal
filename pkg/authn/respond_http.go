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
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"github.com/greenpau/go-identity/pkg/requests"
	"go.uber.org/zap"
	"net/http"
	"net/url"
	"path"
	"strings"
)

func (p *Authenticator) handleHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	p.injectSessionID(ctx, w, r, rr)
	usr, _ := p.authorizeRequest(ctx, w, r, rr)
	switch {
	case r.URL.Path == "/" || r.URL.Path == "/auth" || r.URL.Path == "/auth/":
		p.injectRedirectURL(ctx, w, r, rr)
		return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
	case strings.HasSuffix(r.URL.Path, "/portal"):
		p.logRequest("portal traceback", r, rr)
		return p.handleHTTPPortal(ctx, w, r, rr, usr)
	case strings.HasSuffix(r.URL.Path, "/logout"):
		return p.handleHTTPLogout(ctx, w, r, rr)
	case strings.HasSuffix(r.URL.Path, "/recover"), strings.HasSuffix(r.URL.Path, "/forgot"):
		// TODO(greenpau): implement password recovery.
		return p.handleHTTPRecover(ctx, w, r, rr)
	case strings.Contains(r.URL.Path, "/settings"):
		return p.handleHTTPSettings(ctx, w, r, rr, usr)
	case strings.HasSuffix(r.URL.Path, "/register"):
		return p.handleHTTPRegister(ctx, w, r, rr)
	case strings.HasSuffix(r.URL.Path, "/whoami"):
		return p.handleHTTPWhoami(ctx, w, r, rr, usr)
	case strings.Contains(r.URL.Path, "/saml/"), strings.Contains(r.URL.Path, "/oauth2/"):
		// TODO(greenpau): implement
		return p.handleHTTPExternalLogin(ctx, w, r, rr)
	case strings.Contains(r.URL.Path, "/basic/login/"):
		return p.handleHTTPBasicLogin(ctx, w, r, rr)
	case strings.Contains(r.URL.Path, "/assets/") || strings.Contains(r.URL.Path, "/favicon"):
		return p.handleHTTPStaticAssets(ctx, w, r, rr)
	case strings.HasSuffix(r.URL.Path, "/login"):
		return p.handleHTTPLogin(ctx, w, r, rr, usr)
	}
	p.injectRedirectURL(ctx, w, r, rr)
	if usr != nil {
		p.logger.Debug(
			"no route",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Any("request_path", r.URL.Path),
			zap.Any("user", usr.Claims),
		)
		return p.handleHTTPError(ctx, w, r, rr, http.StatusNotFound)
	}
	return p.handleHTTPErrorWithLog(ctx, w, r, rr, http.StatusNotFound, "no route")
}

func (p *Authenticator) disableClientCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func (p *Authenticator) handleHTTPErrorWithLog(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, code int, msg string) error {
	p.logger.Warn(
		http.StatusText(code),
		zap.String("session_id", rr.Upstream.SessionID),
		zap.String("request_id", rr.ID),
		zap.Any("error", msg),
		zap.String("source_address", utils.GetSourceAddress(r)),
	)
	return p.handleHTTPError(ctx, w, r, rr, code)
}

func (p *Authenticator) handleHTTPError(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, code int) error {
	p.disableClientCache(w)
	resp := p.ui.GetArgs()
	resp.BaseURL(rr.Upstream.BasePath)
	resp.Title = http.StatusText(code)
	resp.Data["authenticated"] = rr.Response.Authenticated
	if r.Referer() != "" {
		resp.Data["go_back_url"] = r.Referer()
	} else {
		resp.Data["go_back_url"] = "/"
	}
	content, err := p.ui.Render("generic", resp)
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}
	return p.handleHTTPRenderHTML(ctx, w, code, content.Bytes())
}

func (p *Authenticator) handleHTTPGeneric(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, code int, msg string) error {
	p.disableClientCache(w)
	resp := p.ui.GetArgs()
	resp.BaseURL(rr.Upstream.BasePath)
	resp.Title = msg
	resp.Data["authenticated"] = rr.Response.Authenticated
	resp.Data["go_back_url"] = rr.Upstream.BasePath
	content, err := p.ui.Render("generic", resp)
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}
	return p.handleHTTPRenderHTML(ctx, w, code, content.Bytes())
}

func (p *Authenticator) handleHTTPRedirect(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, location string) error {
	p.disableClientCache(w)
	location = rr.Upstream.BaseURL + path.Join(rr.Upstream.BasePath, location)
	w.Header().Set("Location", location)
	p.logger.Debug(
		"Redirect served",
		zap.String("session_id", rr.Upstream.SessionID),
		zap.String("request_id", rr.ID),
		zap.String("redirect_url", location),
	)
	w.WriteHeader(http.StatusFound)
	return nil
}

func (p *Authenticator) logRequest(msg string, r *http.Request, rr *requests.Request) {
	p.logger.Debug(
		msg,
		zap.String("session_id", rr.Upstream.SessionID),
		zap.String("request_id", rr.ID),
		zap.String("url_path", r.URL.Path),
		zap.Any("request", rr.Upstream),
		zap.String("source_address", utils.GetSourceAddress(r)),
	)
}

func (p *Authenticator) handleHTTPRenderError(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, err error) error {
	p.logger.Error(
		"Failed HTML response rendering",
		zap.String("session_id", rr.Upstream.SessionID),
		zap.String("request_id", rr.ID),
		zap.String("error", err.Error()),
	)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
	return nil
}

func (p *Authenticator) handleHTTPRenderHTML(ctx context.Context, w http.ResponseWriter, code int, body []byte) error {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(code)
	w.Write(body)
	return nil
}

func (p *Authenticator) handleHTTPRenderPlainText(ctx context.Context, w http.ResponseWriter, code int) error {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(code)
	w.Write([]byte(http.StatusText(code)))
	return nil
}

func (p *Authenticator) injectSessionID(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) {
	if cookie, err := r.Cookie(p.cookie.SessionID); err == nil {
		v, err := url.Parse(cookie.Value)
		if err == nil && v.String() != "" {
			rr.Upstream.SessionID = v.String()
			return
		}
	}
	rr.Upstream.SessionID = utils.GetRandomStringFromRange(64, 96)
	w.Header().Add("Set-Cookie", p.cookie.GetSessionCookie(rr.Upstream.SessionID))
	return
}

func (p *Authenticator) injectRedirectURL(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) {
	if r.Method == "GET" {
		q := r.URL.Query()
		if redirectURL, exists := q["redirect_url"]; exists {
			c := p.cookie.GetCookie(p.cookie.Referer, redirectURL[0])
			p.logger.Debug(
				"redirect recorded",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("redirect_url", c),
			)
			w.Header().Add("Set-Cookie", c)
			rr.Response.RedirectURL = c
		}
	}
}

func (p *Authenticator) authorizeRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) (*user.User, error) {
	extractBasePath(ctx, r, rr)
	usr, err := p.validator.Authorize(ctx, r)
	if err != nil {
		switch err.Error() {
		case "no token found":
			return nil, nil
		default:
			for tokenName := range p.validator.GetAuthCookies() {
				w.Header().Add("Set-Cookie", p.cookie.GetDeleteCookie(tokenName))
			}
			if strings.Contains(r.URL.Path, "/assets/") || strings.Contains(r.URL.Path, "/favicon") {
				return nil, nil
			}
			return nil, err
		}
	}
	if usr != nil {
		rr.Response.Authenticated = true
	}
	return usr, nil
}

func extractBaseURLPath(ctx context.Context, r *http.Request, rr *requests.Request, s string) {
	baseURL, basePath := utils.GetBaseURL(r, s)
	rr.Upstream.BaseURL = baseURL
	if basePath == "/" {
		rr.Upstream.BasePath = basePath
		return
	}
	if strings.HasSuffix(basePath, "/") {
		rr.Upstream.BasePath = basePath
		return
	}
	rr.Upstream.BasePath = basePath + "/"
}

func extractBasePath(ctx context.Context, r *http.Request, rr *requests.Request) {
	switch {
	case r.URL.Path == "/":
		rr.Upstream.BaseURL = utils.GetCurrentBaseURL(r)
		rr.Upstream.BasePath = "/"
	case r.URL.Path == "/auth":
		rr.Upstream.BaseURL = utils.GetCurrentBaseURL(r)
		rr.Upstream.BasePath = "/auth/"
	case strings.HasSuffix(r.URL.Path, "/portal"):
		extractBaseURLPath(ctx, r, rr, "/portal")
	case strings.HasSuffix(r.URL.Path, "/logout"):
		extractBaseURLPath(ctx, r, rr, "/logout")
	case strings.Contains(r.URL.Path, "/settings"):
		extractBaseURLPath(ctx, r, rr, "/settings")
	case strings.HasSuffix(r.URL.Path, "/recover"), strings.HasSuffix(r.URL.Path, "/forgot"):
		extractBaseURLPath(ctx, r, rr, "/recover,/forgot")
	case strings.HasSuffix(r.URL.Path, "/register"):
		extractBaseURLPath(ctx, r, rr, "/register")
	case strings.HasSuffix(r.URL.Path, "/whoami"):
		extractBaseURLPath(ctx, r, rr, "/whoami")
	case strings.Contains(r.URL.Path, "/saml/"), strings.Contains(r.URL.Path, "/oauth2/"):
		extractBaseURLPath(ctx, r, rr, "/saml/,/oauth2/")
	case strings.HasSuffix(r.URL.Path, "/basic/login"):
		extractBaseURLPath(ctx, r, rr, "/basic/login")
	case strings.Contains(r.URL.Path, "/assets/") || strings.Contains(r.URL.Path, "/favicon"):
		extractBaseURLPath(ctx, r, rr, "/assets/")
	case strings.HasSuffix(r.URL.Path, "/login"):
		extractBaseURLPath(ctx, r, rr, "/login")
	case strings.HasPrefix(r.URL.Path, "/auth"):
		rr.Upstream.BaseURL = utils.GetCurrentBaseURL(r)
		rr.Upstream.BasePath = "/auth/"
	default:
		rr.Upstream.BaseURL = utils.GetCurrentBaseURL(r)
		rr.Upstream.BasePath = "/"
	}
}
