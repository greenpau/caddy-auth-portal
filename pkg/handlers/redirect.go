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

package handlers

import (
	"github.com/greenpau/caddy-auth-portal/pkg/cookies"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

// ServeSessionLoginRedirect redirects request to login page.
func ServeSessionLoginRedirect(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	reqID := opts["request_id"].(string)
	log := opts["logger"].(*zap.Logger)
	authURLPath := opts["auth_url_path"].(string)
	cookieNames := opts["cookie_names"].([]string)
	cookies := opts["cookies"].(*cookies.Cookies)

	log.Debug("redirecting to login page",
		zap.String("request_id", reqID),
	)

	for _, k := range cookieNames {
		w.Header().Add("Set-Cookie", k+"=delete;"+cookies.GetDeleteAttributes()+"expires=Thu, 01 Jan 1970 00:00:00 GMT")
	}
	if strings.Contains(r.RequestURI, "?redirect_url=") {
		w.Header().Set("Location", authURLPath)
	} else {
		w.Header().Set("Location", authURLPath+"?redirect_url="+r.RequestURI)
	}
	w.WriteHeader(302)
	return nil
}
