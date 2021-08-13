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
	"encoding/json"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"github.com/greenpau/go-identity/pkg/requests"
	"go.uber.org/zap"
	"net/http"
	"strings"
	"time"
)

// AccessDeniedResponse is the access denied response.
type AccessDeniedResponse struct {
	Error     bool   `json:"error,omitempty" xml:"error,omitempty" yaml:"error,omitempty"`
	Message   string `json:"message,omitempty" xml:"message,omitempty" yaml:"message,omitempty"`
	Timestamp string `json:"timestamp,omitempty" xml:"timestamp,omitempty" yaml:"timestamp,omitempty"`
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
		zap.String("session_id", rr.Upstream.SessionID),
		zap.String("request_id", rr.ID),
		zap.String("error", msg),
	)
	switch code {
	case http.StatusBadRequest:
		return p.handleJSONError(ctx, w, code, "Bad Request")
	case http.StatusForbidden:
		return p.handleJSONError(ctx, w, code, "Forbidden")
	case http.StatusInternalServerError:
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
	p.disableClientCache(w)
	p.injectSessionID(ctx, w, r, rr)
	w.Header().Set("Content-Type", "application/json")
	p.logger.Debug(
		"Received JSON API request",
		zap.String("session_id", rr.Upstream.SessionID),
		zap.String("request_id", rr.ID),
		zap.String("url_path", r.URL.Path),
		zap.String("source_address", utils.GetSourceAddress(r)),
	)

	usr, err := p.authorizeRequest(ctx, w, r, rr)
	if err != nil {
		return p.handleJSONErrorWithLog(ctx, w, r, rr, http.StatusUnauthorized, err.Error())
	}

	switch {
	case strings.Contains(r.URL.Path, "/login"):
		return p.handleJSONLogin(ctx, w, r, rr)
	case strings.Contains(r.URL.Path, "/whoami"):
		return p.handleJSONWhoami(ctx, w, r, rr, usr)
	}

	if usr != nil {
		p.logger.Debug(
			"No route found",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Any("user", usr.Claims),
		)
		return p.handleJSONError(ctx, w, http.StatusBadRequest, "Bad Request")
	}
	return p.handleJSONError(ctx, w, http.StatusUnauthorized, "Access denied")
}
