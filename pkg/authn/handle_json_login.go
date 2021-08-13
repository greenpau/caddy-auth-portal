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
	"github.com/greenpau/go-identity/pkg/requests"
	"net/http"
)

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

func (p *Authenticator) handleJSONLogin(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	authRequest := &AuthRequest{}
	if r.Method != "POST" {
		return p.handleJSONError(ctx, w, http.StatusUnauthorized, "Authentication Required")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	respDecoder := json.NewDecoder(r.Body)
	respDecoder.DisallowUnknownFields()
	if err := respDecoder.Decode(authRequest); err != nil {
		return p.handleJSONErrorWithLog(ctx, w, r, rr, http.StatusBadRequest, err.Error())
	}

	rr.Response.Workflow = "json-api"
	credentials := map[string]string{
		"username": authRequest.Username,
		"password": authRequest.Password,
		"realm":    authRequest.Realm,
	}

	if err := p.authenticateLoginRequest(ctx, w, r, rr, credentials); err != nil {
		return p.handleJSONErrorWithLog(ctx, w, r, rr, rr.Response.Code, err.Error())
	}
	if err := p.authorizeLoginRequest(ctx, w, r, rr); err != nil {
		return p.handleJSONErrorWithLog(ctx, w, r, rr, rr.Response.Code, err.Error())
	}
	usr, err := p.sessions.Get(rr.Upstream.SessionID)
	if err != nil {
		return p.handleJSONErrorWithLog(ctx, w, r, rr, http.StatusInternalServerError, err.Error())
	}
	resp := &AuthResponse{
		TokenName: usr.TokenName,
		Token:     usr.Token,
	}
	respBytes, _ := json.Marshal(resp)
	w.WriteHeader(rr.Response.Code)
	w.Write(respBytes)
	return nil
}
