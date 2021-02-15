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
	"github.com/greenpau/caddy-auth-portal/pkg/ui"
	"go.uber.org/zap"
	"net/http"
)

// ServeSandbox performs second factore authentication.
func ServeSandbox(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	reqID := opts["request_id"].(string)
	log := opts["logger"].(*zap.Logger)
	ui := opts["ui"].(*ui.UserInterfaceFactory)
	//cookies := opts["cookies"].(*cookies.Cookies)
	// authURLPath := opts["auth_url_path"].(string)
	//redirectToToken := opts["redirect_token_name"].(string)

	/*
		if !opts["authenticated"].(bool) {
			w.Header().Set("Location", authURLPath)
			w.WriteHeader(302)
			return nil
		}
	*/

	// Display main authentication portal page
	resp := ui.GetArgs()
	resp.Title = "Sandbox"
	resp.Data["sandbox_id"] = "foobar"
	// resp.Data["sandbox_action"] = "register"
	//resp.Data["registration_required"] = "yes"
	resp.Data["sandbox_action"] = "register"
	resp.Data["registration_required"] = "yes"

	content, err := ui.Render("sandbox", resp)
	if err != nil {
		log.Error("Failed HTML response rendering", zap.String("request_id", reqID), zap.String("error", err.Error()))
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(500)
		w.Write([]byte(`Internal Server Error`))
		return err
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write(content.Bytes())
	return nil
}
