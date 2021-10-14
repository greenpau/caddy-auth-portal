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
	"github.com/greenpau/caddy-auth-portal/pkg/backends"
	"github.com/greenpau/caddy-auth-portal/pkg/enums/operator"
	// "github.com/greenpau/caddy-auth-portal/pkg/utils"
	"github.com/greenpau/go-identity/pkg/requests"
	// "go.uber.org/zap"
	"net/http"
	"strings"
)

func (p *Authenticator) handleHTTPAPIKeysSettings(
	ctx context.Context, r *http.Request, rr *requests.Request,
	usr *user.User, backend *backends.Backend, data map[string]interface{},
) error {
	var action string
	var status bool
	entrypoint := "apikeys"
	data["view"] = entrypoint
	endpoint, err := getEndpoint(r.URL.Path, "/"+entrypoint)
	if err != nil {
		return err
	}
	switch {
	case strings.HasPrefix(endpoint, "/add") && r.Method == "POST":
		action = "add"
		data["status"] = "FAIL"
		rr.User.Username = usr.Claims.Subject
		rr.User.Email = usr.Claims.Email
		if err = backend.Request(operator.AddAPIKey, rr); err != nil {
			data["status_reason"] = fmt.Sprintf("%v", err)
			break
		}
		data["status"] = "SUCCESS"
		data["status_reason"] = "API key has been added"
	case strings.HasPrefix(endpoint, "/add"):
		action = "add"
		status = true
	case strings.HasPrefix(endpoint, "/delete") && r.Method == "POST":
		action = "delete"
		data["status"] = "FAIL"
		keyID, _ := getEndpoint(endpoint, "/delete")
		rr.User.Username = usr.Claims.Subject
		rr.User.Email = usr.Claims.Email
		rr.Query.ID = keyID
		if err = backend.Request(operator.DeleteAPIKey, rr); err != nil {
			data["status_reason"] = fmt.Sprintf("%v", err)
			break
		}
		data["status"] = "SUCCESS"
		data["status_reason"] = "API key has been deleted"
	case strings.HasPrefix(endpoint, "/delete"):
		action = "delete"
		status = true
	case strings.HasPrefix(endpoint, "/view"):
		action = "view"
		// TODO(greenpau): add listing
	}
	attachView(data, entrypoint, action, status)
	return nil
}
