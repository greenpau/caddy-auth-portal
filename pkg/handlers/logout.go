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
)

// ServeSessionLogoff performs session logout sequence.
func ServeSessionLogoff(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	reqID := opts["request_id"].(string)
	log := opts["logger"].(*zap.Logger)
	cookies := opts["cookies"].(*cookies.Cookies)
	authURLPath := opts["auth_url_path"].(string)
	cookieNames := opts["cookie_names"].([]string)

	log.Debug("serve logout redirect",
		zap.String("request_id", reqID),
	)

	for _, cookieName := range cookieNames {
		w.Header().Add("Set-Cookie", cookieName+"=delete;"+cookies.GetDeleteAttributes()+" expires=Thu, 01 Jan 1970 00:00:00 GMT")
	}
	if v, exists := opts["redirect_url"]; exists {
		w.Header().Set("Location", authURLPath+"?redirect_url="+v.(string))
	} else {
		w.Header().Set("Location", authURLPath)
	}
	w.WriteHeader(303)
	return nil
}
