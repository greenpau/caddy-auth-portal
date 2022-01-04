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
)

func (p *Authenticator) handleHTTPGeneralSettings(
	ctx context.Context, r *http.Request, rr *requests.Request,
	usr *user.User, backend *backends.Backend, data map[string]interface{},
) error {
	data["view"] = "general"
	err := backend.Request(operator.GetUser, rr)
	if err != nil {
		attachFailStatus(data, fmt.Sprintf("%v", err))
		return nil
	}
	user := rr.Response.Payload.(*identity.User)
	data["metadata"] = user.GetMetadata()

	attachSuccessStatus(data, "User identity has been discovered")
	return nil
}
