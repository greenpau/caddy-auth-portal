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
	"github.com/greenpau/caddy-auth-portal/pkg/backends"
	"github.com/greenpau/caddy-auth-portal/pkg/enums/operator"
	"github.com/greenpau/caddy-authorize/pkg/user"
	// "github.com/greenpau/caddy-auth-portal/pkg/utils"
	"github.com/greenpau/go-identity"
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
		status = true
		if err := validateAPIKeyInputForm(r, rr); err != nil {
			attachFailStatus(data, "Bad Request")
			break
		}
		rr.Key.Usage = "api"
		if err = backend.Request(operator.AddAPIKey, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("%v", err))
			break
		}
		data["api_key"] = rr.Response.Payload.(string)
		attachSuccessStatus(data, "New API key has been added")
	case strings.HasPrefix(endpoint, "/add"):
		action = "add"
	case strings.HasPrefix(endpoint, "/delete"):
		action = "delete"
		status = true
		keyID, err := getEndpointKeyID(endpoint, "/delete/")
		if err != nil {
			attachFailStatus(data, fmt.Sprintf("%v", err))
			break
		}
		rr.Key.ID = keyID
		if err = backend.Request(operator.DeleteAPIKey, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("failed deleting key id %s: %v", keyID, err))
			break
		}
		attachSuccessStatus(data, fmt.Sprintf("key id %s deleted successfully", keyID))
	default:
		// List API Keys.
		rr.Key.Usage = "api"
		if err = backend.Request(operator.GetAPIKeys, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("%v", err))
			break
		}
		bundle := rr.Response.Payload.(*identity.APIKeyBundle)
		pubKeys := bundle.Get()
		if len(pubKeys) > 0 {
			data[entrypoint] = pubKeys
		}

	}
	attachView(data, entrypoint, action, status)
	return nil
}
