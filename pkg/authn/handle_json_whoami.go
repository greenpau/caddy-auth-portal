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
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
	"github.com/greenpau/go-identity/pkg/requests"
	"net/http"
)

func (p *Authenticator) handleJSONWhoami(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, usr *user.User) error {
	if usr == nil {
		return p.handleJSONError(ctx, w, http.StatusUnauthorized, "Access denied")
	}
	respBytes, _ := json.Marshal(usr.Claims)
	w.WriteHeader(200)
	w.Write(respBytes)
	return nil
}
