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
	"fmt"
	"net/http"
	// "path"
	"strings"
	"time"
	//jwtclaims "github.com/greenpau/caddy-auth-jwt/pkg/claims"
	// "github.com/greenpau/caddy-auth-jwt/pkg/kms"
	//jwtvalidator "github.com/greenpau/caddy-auth-jwt/pkg/validator"
	//"github.com/greenpau/caddy-auth-portal/pkg/backends"
	//"github.com/greenpau/caddy-auth-portal/pkg/cache"
	//"github.com/greenpau/caddy-auth-portal/pkg/cookie"
	// "github.com/greenpau/caddy-auth-portal/pkg/handlers"
	//"github.com/greenpau/caddy-auth-portal/pkg/registration"
	//"github.com/greenpau/caddy-auth-portal/pkg/ui"
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
	"github.com/greenpau/caddy-auth-portal/pkg/enums/operator"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"github.com/greenpau/go-identity/pkg/requests"
	"go.uber.org/zap"
)

// AccessDeniedResponse is the access denied response.
type AccessDeniedResponse struct {
	Error     bool   `json:"error,omitempty" xml:"error,omitempty" yaml:"error,omitempty"`
	Message   string `json:"message,omitempty" xml:"message,omitempty" yaml:"message,omitempty"`
	Timestamp string `json:"timestamp,omitempty" xml:"timestamp,omitempty" yaml:"timestamp,omitempty"`
}

// AuthRequest is authentication request.
type AuthRequest struct {
	Username string `json:"username,omitempty" xml:"username" yaml:"username,omitempty"`
	Password string `json:"password,omitempty" xml:"password" yaml:"password,omitempty"`
	Realm    string `json:"realm,omitempty" xml:"realm" yaml:"realm,omitempty"`
}

// AuthResponse is the response to authentication request.
type AuthResponse struct {
	Token     string `json:"token,omitempty" xml:"token,omitempty" yaml:"token,omitempty"`
	TokenName string `json:"token_name,omitempty" xml:"token_name,omitempty" yaml:"token_name,omitempty"`
}

func newAccessDeniedResponse(msg string) *AccessDeniedResponse {
	return &AccessDeniedResponse{
		Error:     true,
		Message:   msg,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func (p *Authenticator) handleJSONErrorWithLog(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, code int, msg string) error {
	p.logger.Warn(
		"Access denied",
		zap.String("request_id", rr.ID),
		zap.Any("error", msg),
		zap.String("source_address", utils.GetSourceAddress(r)),
	)
	switch code {
	case 400:
		return p.handleJSONError(ctx, w, code, "Bad Request")
	case 403:
		return p.handleJSONError(ctx, w, code, "Forbidden")
	case 500:
		return p.handleJSONError(ctx, w, code, "Internal Server Error")
	}
	return p.handleJSONError(ctx, w, code, "Access denied")
}

func (p *Authenticator) handleJSONError(ctx context.Context, w http.ResponseWriter, code int, msg string) error {
	resp := newAccessDeniedResponse(msg)
	respBytes, _ := json.Marshal(resp)
	w.WriteHeader(code)
	w.Write(respBytes)
	return nil
}

func (p *Authenticator) handleJSON(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	// p.logger.Debug("Received API request", zap.String("request_id", rr.ID), zap.Any("request_path", r.URL.Path), zap.Any("auth_url", p.AuthURLPath))
	usr, err := p.validator.Authorize(ctx, r)
	if err != nil {
		switch err.Error() {
		case "no token found":
		default:
			return p.handleJSONErrorWithLog(ctx, w, r, rr, 401, err.Error())
		}
	} else {
		rr.Response.Authenticated = true
	}

	switch {
	case strings.Contains(r.URL.Path, "/login"):
		return p.handleJSONLogin(ctx, w, r, rr)
	case strings.Contains(r.URL.Path, "/whoami"):
		return p.handleJSONWhoami(ctx, w, r, rr, usr)
	}
	if usr != nil {
		p.logger.Debug("no route", zap.String("request_id", rr.ID), zap.Any("request_path", r.URL.Path), zap.Any("user", usr.Claims))
		return p.handleJSONError(ctx, w, 400, "Bad Request")
	}
	return p.handleJSONError(ctx, w, 401, "Access denied")
}

func (p *Authenticator) handleJSONWhoami(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, usr *user.User) error {
	if usr == nil {
		return p.handleJSONError(ctx, w, 401, "Access denied")
	}
	respBytes, _ := json.Marshal(usr.Claims)
	w.WriteHeader(200)
	w.Write(respBytes)
	return nil
}

func (p *Authenticator) handleJSONLogin(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	authRequest := &AuthRequest{}
	if r.Method != "POST" {
		return p.handleJSONError(ctx, w, 401, "Authentication Required")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	respDecoder := json.NewDecoder(r.Body)
	respDecoder.DisallowUnknownFields()
	if err := respDecoder.Decode(authRequest); err != nil {
		return p.handleJSONErrorWithLog(ctx, w, r, rr, 400, err.Error())
	}
	for _, backend := range p.backends {
		if backend.GetRealm() != authRequest.Realm {
			continue
		}
		rr.User.Username = authRequest.Username
		rr.User.Password = authRequest.Password
		err := backend.Request(operator.Authenticate, rr)
		if err != nil {
			return p.handleJSONErrorWithLog(ctx, w, r, rr, 401, err.Error())
		}

		switch m := rr.Response.Payload.(type) {
		case map[string]interface{}:
			m["jti"] = rr.ID
			m["exp"] = time.Now().Add(time.Duration(p.keystore.GetTokenLifetime(nil, nil)) * time.Second).UTC().Unix()
			m["iat"] = time.Now().UTC().Unix()
			m["nbf"] = time.Now().Add(time.Duration(60) * time.Second * -1).UTC().Unix()
			m["origin"] = backend.GetRealm()
			m["iss"] = utils.GetCurrentURL(r)
			m["addr"] = utils.GetSourceAddress(r)
			usr, err := user.NewUser(m)
			if err != nil {
				return p.handleJSONErrorWithLog(ctx, w, r, rr, 401, err.Error())
			}
			if err := p.keystore.SignToken(nil, nil, usr); err != nil {
				return p.handleJSONErrorWithLog(ctx, w, r, rr, 500, err.Error())
			}
			usr.Authenticator.Name = backend.GetName()
			usr.Authenticator.Realm = backend.GetRealm()
			usr.Authenticator.Method = backend.GetMethod()
			p.logger.Info("Successful login", zap.String("request_id", rr.ID), zap.Any("backend", usr.Authenticator), zap.Any("user", m))
			p.sessions.Add(rr.ID, usr)
			w.Header().Set("Authorization", "Bearer "+usr.Token)
			w.Header().Set("Set-Cookie", p.cookie.GetCookie(usr.TokenName, usr.Token))
			resp := &AuthResponse{
				TokenName: usr.TokenName,
				Token:     usr.Token,
			}
			respBytes, _ := json.Marshal(resp)
			w.WriteHeader(200)
			w.Write(respBytes)
			return nil
		default:
			return p.handleJSONErrorWithLog(ctx, w, r, rr, 400, fmt.Sprintf("unsupported backend response payload %T", m))
		}
	}

	return p.handleJSONErrorWithLog(ctx, w, r, rr, 400, "no matching realm")
}
