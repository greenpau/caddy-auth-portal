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
	// "github.com/greenpau/caddy-auth-portal/pkg/utils"
	"github.com/greenpau/go-identity/pkg/requests"
	// "go.uber.org/zap"
	"net/http"
	"strings"
)

func (p *Authenticator) handleHTTPPasswordSettings(
	ctx context.Context, r *http.Request, rr *requests.Request,
	usr *user.User, backend *backends.Backend, data map[string]interface{},
) error {
	var action string
	var status bool
	entrypoint := "password"
	data["view"] = entrypoint
	endpoint, err := getEndpoint(r.URL.Path, "/"+entrypoint)
	if err != nil {
		return err
	}
	switch {
	case strings.HasPrefix(endpoint, "/edit") && r.Method == "POST":
		action = "edit"
		if err := validatePasswordChangeForm(r, rr); err != nil {
			attachFailStatus(data, "Bad Request")
			break
		}
		if err = backend.Request(operator.ChangePassword, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("%v", err))
			break
		}
		attachSuccessStatus(data, "Password has been changed")
	}
	attachView(data, entrypoint, action, status)
	return nil
}
