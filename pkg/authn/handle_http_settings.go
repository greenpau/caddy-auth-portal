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
	"fmt"
	"github.com/greenpau/caddy-authorize/pkg/user"
	addrutils "github.com/greenpau/caddy-authorize/pkg/utils/addr"
	"github.com/greenpau/go-identity/pkg/requests"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

func (p *Authenticator) handleHTTPSettings(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, parsedUser *user.User) error {
	p.disableClientCache(w)
	p.injectRedirectURL(ctx, w, r, rr)
	if parsedUser == nil {
		if rr.Response.RedirectURL == "" {
			return p.handleHTTPRedirect(ctx, w, r, rr, "/login?redirect_url="+r.RequestURI)
		}
		return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
	}

	usr, err := p.sessions.Get(parsedUser.Claims.ID)
	if err != nil {
		p.logger.Warn(
			"jti session not found",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("jti", parsedUser.Claims.ID),
			zap.Any("error", err),
			zap.String("source_address", addrutils.GetSourceAddress(r)),
		)
		return p.handleHTTPLogoutWithLocalRedirect(ctx, w, r, rr)
	}

	backend := p.getBackendByRealm(usr.Authenticator.Realm)
	if backend == nil {
		p.logger.Warn(
			"backend not found",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("realm", usr.Authenticator.Realm),
			zap.String("jti", parsedUser.Claims.ID),
			zap.String("source_address", addrutils.GetSourceAddress(r)),
		)
		return p.handleHTTPLogoutWithLocalRedirect(ctx, w, r, rr)
	}

	if permitted := usr.HasRole("authp/admin", "authp/user"); !permitted {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusForbidden)
	}

	switch usr.Authenticator.Method {
	case "local":
	default:
		return p.handleHTTPGeneric(ctx, w, r, rr, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
	}

	endpoint, err := getEndpoint(r.URL.Path, "/settings")
	if err != nil {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
	}

	p.logger.Debug(
		"Rendering settings page",
		zap.String("session_id", rr.Upstream.SessionID),
		zap.String("request_id", rr.ID),
		zap.String("realm", usr.Authenticator.Realm),
		zap.String("jti", parsedUser.Claims.ID),
		zap.String("source_address", addrutils.GetSourceAddress(r)),
		zap.String("endpoint", endpoint),
	)

	resp := p.ui.GetArgs()
	resp.Title = "Settings"
	resp.BaseURL(rr.Upstream.BasePath)

	// Populate username (sub) and email address (email)
	rr.User.Username = usr.Claims.Subject
	rr.User.Email = usr.Claims.Email

	switch {
	case strings.HasPrefix(endpoint, "/password"):
		if err := p.handleHTTPPasswordSettings(ctx, r, rr, usr, backend, resp.Data); err != nil {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
		}
	case strings.HasPrefix(endpoint, "/apikeys"):
		if err := p.handleHTTPAPIKeysSettings(ctx, r, rr, usr, backend, resp.Data); err != nil {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
		}
	case strings.HasPrefix(endpoint, "/sshkeys"):
		if err := p.handleHTTPSSHKeysSettings(ctx, r, rr, usr, backend, resp.Data); err != nil {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
		}
	case strings.HasPrefix(endpoint, "/gpgkeys"):
		if err := p.handleHTTPGPGKeysSettings(ctx, r, rr, usr, backend, resp.Data); err != nil {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
		}
	case strings.HasPrefix(endpoint, "/mfa/barcode/"):
		return p.handleHTTPMfaBarcode(ctx, w, r, endpoint)
	case strings.HasPrefix(endpoint, "/mfa"):
		if err := p.handleHTTPMfaSettings(ctx, r, rr, usr, backend, resp.Data); err != nil {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
		}
	case strings.HasPrefix(endpoint, "/connected"):
		resp.Data["view"] = "connected"
	default:
		if err := p.handleHTTPGeneralSettings(ctx, r, rr, usr, backend, resp.Data); err != nil {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
		}
	}
	content, err := p.ui.Render("settings", resp)
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}
	return p.handleHTTPRenderHTML(ctx, w, http.StatusOK, content.Bytes())
}

func getEndpoint(p, s string) (string, error) {
	i := strings.Index(p, s)
	if i < 0 {
		return s, fmt.Errorf("%s is not in %s", p, s)
	}
	return strings.TrimPrefix(p[i:], s), nil
}

func getEndpointKeyID(p, s string) (string, error) {
	sp, err := getEndpoint(p, s)
	if err != nil {
		return "", err
	}
	arr := strings.Split(sp, "/")
	if len(arr) != 1 {
		return "", fmt.Errorf("invalid key id")
	}
	return arr[0], nil
}

func attachView(data map[string]interface{}, entrypoint, action string, status bool) {
	if action == "" {
		data["view"] = entrypoint
		return
	}
	if status {
		data["view"] = fmt.Sprintf("%s-%s-status", entrypoint, action)
		return
	}
	data["view"] = fmt.Sprintf("%s-%s", entrypoint, action)
}

func attachStatus(data map[string]interface{}, status, statusText string) {
	data["status"] = status
	data["status_reason"] = statusText
}

func attachSuccessStatus(data map[string]interface{}, statusText string) {
	attachStatus(data, "SUCCESS", statusText)
}

func attachFailStatus(data map[string]interface{}, statusText string) {
	attachStatus(data, "FAIL", statusText)
}
