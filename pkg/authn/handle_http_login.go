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
	"strings"
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
	code, err = p.authorizeLoginRequest(ctx, w, r, rr)
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
	rr.Flags.Enabled = true
	err := backend.Request(operator.Authenticate, rr)
	if err != nil {
		return http.StatusUnauthorized, err
	}
	return http.StatusOK, nil
}

func (p *Authenticator) authorizeLoginRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) (int, error) {
	backend := p.getBackendByRealm(rr.Upstream.Realm)
	if backend == nil {
		return http.StatusBadRequest, fmt.Errorf("no matching realm found")
	}
	switch m := rr.Response.Payload.(type) {
	case map[string]interface{}:
		m["jti"] = rr.Upstream.SessionID
		m["exp"] = time.Now().Add(time.Duration(p.keystore.GetTokenLifetime(nil, nil)) * time.Second).UTC().Unix()
		m["iat"] = time.Now().UTC().Unix()
		m["nbf"] = time.Now().Add(time.Duration(60) * time.Second * -1).UTC().Unix()
		m["origin"] = rr.Upstream.Realm
		m["iss"] = utils.GetCurrentURL(r)
		m["addr"] = utils.GetSourceAddress(r)
		// Perform user claim transformation if necessary.
		if p.transformer != nil {
			m["realm"] = rr.Upstream.Realm
			if err := p.transformer.Transform(m); err != nil {
				p.logger.Warn(
					"user transformation failed",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.Any("user", m),
					zap.Error(err),
				)
				return http.StatusInternalServerError, err
			}
			p.logger.Debug(
				"user transformation ended",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Any("user", m),
			)
		}
		injectPortalRoles(m)
		usr, err := user.NewUser(m)
		if err != nil {
			return http.StatusUnauthorized, err
		}
		if err := p.keystore.SignToken(nil, nil, usr); err != nil {
			p.logger.Warn(
				"user token signing failed",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Any("user", m),
				zap.Error(err),
			)
			return http.StatusInternalServerError, err
		}
		usr.Authenticator.Name = backend.GetName()
		usr.Authenticator.Realm = backend.GetRealm()
		usr.Authenticator.Method = backend.GetMethod()

		// Build a list of additional verification/acceptance challenges.
		if v, exists := m["challenges"]; exists {
			// Create checkpoints based on user transforms.
			checkpoints, err := user.NewCheckpoints(v)
			if err != nil {
				p.logger.Warn(
					"checkpoint creation failed",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.Any("user", m),
					zap.Error(err),
				)
				return http.StatusInternalServerError, err
			}
			usr.Checkpoints = checkpoints
		}

		// Build a list of additional user-specific UI links.
		if v, exists := m["frontend_links"]; exists {
			if err := usr.AddFrontendLinks(v); err != nil {
				p.logger.Warn(
					"frontend link creation failed",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.Any("user", m),
					zap.Error(err),
				)
				return http.StatusInternalServerError, err
			}
		}

		if len(usr.Checkpoints) > 0 {
			p.logger.Info(
				"Successful login and redirect to authorization checkpoints",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Any("backend", usr.Authenticator),
				zap.Any("user", m),
				zap.Any("checkpoints", usr.Checkpoints),
			)
			// Grant temporary guest cookie and redirect to sandbox URL.
			usr.Authenticator.TempSessionID = utils.GetRandomStringFromRange(36, 48)
			usr.Authenticator.TempSecret = utils.GetRandomStringFromRange(36, 48)
			if err := p.sandboxes.Add(usr.Authenticator.TempSessionID, usr); err != nil {
				p.logger.Warn(
					"Failed creating sandbox sessions",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.Any("backend", usr.Authenticator),
					zap.Any("user", m),
					zap.Any("checkpoints", usr.Checkpoints),
				)
			}
			redirectLocation := fmt.Sprintf("%s%s/%s",
				rr.Upstream.BaseURL,
				path.Join(rr.Upstream.BasePath, "/sandbox/"),
				usr.Authenticator.TempSessionID,
			)
			w.Header().Set("Set-Cookie", p.cookie.GetCookie(p.cookie.SandboxID, usr.Authenticator.TempSecret))
			w.Header().Set("Location", redirectLocation)
			return http.StatusSeeOther, nil
			// return http.StatusNotImplemented, fmt.Errorf("Checkpoints Not Implemented")
		}
		p.logger.Info(
			"Successful login",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Any("backend", usr.Authenticator),
			zap.Any("user", m),
		)
		return p.grantAccess(ctx, w, r, rr, usr), nil
	}
	return http.StatusBadRequest, fmt.Errorf("unsupported backend response payload %T", rr.Response.Payload)
}

func (p *Authenticator) grantAccess(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, usr *user.User) int {
	var redirectLocation string
	rr.Response.Authenticated = true
	usr.Authorized = true
	p.sessions.Add(rr.Upstream.SessionID, usr)
	w.Header().Set("Authorization", "Bearer "+usr.Token)
	w.Header().Set("Set-Cookie", p.cookie.GetCookie(usr.TokenName, usr.Token))
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
	return http.StatusSeeOther
}

func injectPortalRoles(m map[string]interface{}) {
	var roles, updatedRoles []string
	var reservedRoleFound bool
	roleMap := make(map[string]bool)
	reservedRoles := map[string]bool{
		"authp/admin": false,
		"authp/user":  false,
		"authp/guest": false,
	}

	v, exists := m["roles"]
	if !exists {
		m["roles"] = []string{"authp/guest"}
		return
	}
	switch val := v.(type) {
	case string:
		roles = strings.Split(val, " ")
	case []string:
		roles = val
	case []interface{}:
		for _, entry := range val {
			switch e := entry.(type) {
			case string:
				roles = append(roles, e)
			}
		}
	}
	for _, roleName := range roles {
		roleName = strings.TrimSpace(roleName)
		if roleName == "" {
			continue
		}
		if _, exists := roleMap[roleName]; exists {
			continue
		}
		if _, exists := reservedRoles[roleName]; exists {
			reservedRoles[roleName] = true
			reservedRoleFound = true
		}
		roleMap[roleName] = true
		updatedRoles = append(updatedRoles, roleName)
	}
	if !reservedRoleFound {
		updatedRoles = append(updatedRoles, "authp/guest")
	}
	m["roles"] = updatedRoles
	return
}
