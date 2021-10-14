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
	"fmt"
	"github.com/greenpau/caddy-authorize/pkg/user"
	"github.com/greenpau/caddy-auth-portal/pkg/backends"
	"github.com/greenpau/caddy-auth-portal/pkg/enums/operator"
	"github.com/greenpau/go-identity"
	"github.com/greenpau/go-identity/pkg/requests"
	"net/http"
	"strings"
)

func (p *Authenticator) handleHTTPGPGKeysSettings(
	ctx context.Context, r *http.Request, rr *requests.Request,
	usr *user.User, backend *backends.Backend, data map[string]interface{},
) error {
	var action string
	var status bool
	entrypoint := "gpgkeys"
	data["view"] = entrypoint
	endpoint, err := getEndpoint(r.URL.Path, "/"+entrypoint)
	if err != nil {
		return err
	}
	switch {
	case strings.HasPrefix(endpoint, "/add") && r.Method == "POST":
		// Add GPG key.
		action = "add"
		status = true
		if err := validateKeyInputForm(r, rr); err != nil {
			attachFailStatus(data, "Bad Request")
			break
		}
		rr.Key.Usage = "gpg"
		if err = backend.Request(operator.AddKeyGPG, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("%v", err))
			break
		}
		attachSuccessStatus(data, "Public GPG key has been added")
	case strings.HasPrefix(endpoint, "/add"):
		action = "add"
	case strings.HasPrefix(endpoint, "/delete"):
		// Delete a particular GPG key.
		action = "delete"
		status = true
		keyID, err := getEndpointKeyID(endpoint, "/delete/")
		if err != nil {
			attachFailStatus(data, fmt.Sprintf("%v", err))
			break
		}
		rr.Key.ID = keyID
		if err = backend.Request(operator.DeletePublicKey, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("failed deleting key id %s: %v", keyID, err))
			break
		}
		attachSuccessStatus(data, fmt.Sprintf("key id %s deleted successfully", keyID))
	case strings.HasPrefix(endpoint, "/view"):
		// Get a particular GPG key.
		action = "view"
		keyID, err := getEndpointKeyID(endpoint, "/view/")
		if err != nil {
			attachFailStatus(data, fmt.Sprintf("%v", err))
			break
		}
		rr.Key.Usage = "gpg"
		if err = backend.Request(operator.GetPublicKeys, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("failed fetching key id %s: %v", keyID, err))
			break
		}
		bundle := rr.Response.Payload.(*identity.PublicKeyBundle)
		for _, k := range bundle.Get() {
			if k.ID != keyID {
				continue
			}
			var keyMap map[string]interface{}
			keyBytes, _ := json.Marshal(k)
			json.Unmarshal(keyBytes, &keyMap)
			for _, w := range []string{"payload"} {
				if _, exists := keyMap[w]; !exists {
					continue
				}
				delete(keyMap, w)
			}
			prettyKey, _ := json.MarshalIndent(keyMap, "", "  ")
			attachSuccessStatus(data, "OK")
			data["key"] = string(prettyKey)
			if k.Payload != "" {
				data["pem_key"] = k.Payload
			}
			break
		}
	default:
		// List GPG Keys.
		rr.Key.Usage = "gpg"
		if err = backend.Request(operator.GetPublicKeys, rr); err != nil {
			attachFailStatus(data, fmt.Sprintf("%v", err))
			break
		}
		bundle := rr.Response.Payload.(*identity.PublicKeyBundle)
		pubKeys := bundle.Get()
		if len(pubKeys) > 0 {
			data[entrypoint] = pubKeys
		}
	}
	attachView(data, entrypoint, action, status)
	return nil
}
