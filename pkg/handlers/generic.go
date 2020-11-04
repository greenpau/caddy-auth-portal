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
	"encoding/json"
	"github.com/greenpau/caddy-auth-portal/pkg/ui"
	"go.uber.org/zap"
	"net/http"
)

// ServeGeneric returns generic response page.
func ServeGeneric(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	var title string
	reqID := opts["request_id"].(string)
	flow := opts["flow"].(string)
	log := opts["logger"].(*zap.Logger)
	ui := opts["ui"].(*ui.UserInterfaceFactory)
	authURLPath := opts["auth_url_path"].(string)

	statusCode := 200
	switch flow {
	case "not_found":
		title = "Not Found"
		statusCode = 404
	case "auth_failed":
		statusCode = 401
		title = "Authentication Failed"
	case "backend_not_found":
		title = "Authentication Backend Not Found"
		statusCode = 404
	case "malformed_backend":
		title = "Malformed Authentication Backend"
	case "unsupported_feature":
		title = "Unsupported Feature"
		statusCode = 404
	case "policy_violation":
		title = "Policy Violation"
		statusCode = 400
	case "internal_server_error":
		title = "Internal Server Error"
		statusCode = 500
	default:
		title = "Unsupported Flow"
		statusCode = 400
	}

	log.Debug("serve generic page",
		zap.String("request_id", reqID),
		zap.String("title", title),
		zap.Int("status_code", statusCode),
	)

	// If the requested content type is JSON, then output authenticated message
	if opts["content_type"].(string) == "application/json" {
		resp := make(map[string]interface{})
		resp["message"] = title
		if opts["authenticated"].(bool) {
			resp["authenticated"] = true
		}
		payload, err := json.Marshal(resp)
		if err != nil {
			log.Error("Failed JSON response rendering", zap.String("request_id", reqID), zap.String("error", err.Error()))
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(500)
			w.Write([]byte(`Internal Server Error`))
			return err
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		w.Write(payload)
		return nil
	}

	// Display main authentication portal page
	resp := ui.GetArgs()
	resp.Title = title
	resp.Data["go_back_url"] = authURLPath
	if opts["authenticated"].(bool) {
		resp.Data["authenticated"] = true
		referer := r.Referer()
		if referer != "" {
			resp.Data["go_back_url"] = referer
		}
	} else {
		resp.Data["authenticated"] = false
	}
	content, err := ui.Render("generic", resp)
	if err != nil {
		log.Error("Failed HTML response rendering", zap.String("request_id", reqID), zap.String("error", err.Error()))
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(500)
		w.Write([]byte(`Internal Server Error`))
		return err
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(statusCode)
	w.Write(content.Bytes())
	return nil
}
