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
	jwtclaims "github.com/greenpau/caddy-auth-jwt/pkg/claims"

	"github.com/greenpau/caddy-auth-portal/pkg/ui"
	"go.uber.org/zap"
	"net/http"
	"time"
)

// ServeWhoami returns authenticated user information.
func ServeWhoami(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	reqID := opts["request_id"].(string)
	log := opts["logger"].(*zap.Logger)
	uiFactory := opts["ui"].(*ui.UserInterfaceFactory)
	authURLPath := opts["auth_url_path"].(string)

	if !opts["authenticated"].(bool) {
		w.Header().Set("Location", authURLPath+"?redirect_url="+r.RequestURI)
		w.WriteHeader(302)
		return nil
	}

	claims := opts["user_claims"].(*jwtclaims.UserClaims)
	// If the requested content type is JSON, then output authenticated message
	if opts["content_type"].(string) == "application/json" {
		payload, err := json.Marshal(claims)
		if err != nil {
			log.Error("Failed JSON response rendering", zap.String("request_id", reqID), zap.String("error", err.Error()))
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(500)
			w.Write([]byte(`Internal Server Error`))
			return err
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(payload)
		return nil
	}

	// Display main authentication portal page
	resp := uiFactory.GetArgs()
	resp.Title = "User Identity"
	tokenMap := claims.AsMap()
	tokenMap["authenticated"] = true
	if claims.ExpiresAt > 0 {
		tokenMap["expires_at_utc"] = time.Unix(claims.ExpiresAt, 0).Format(time.UnixDate)
	}
	if claims.IssuedAt > 0 {
		tokenMap["issued_at_utc"] = time.Unix(claims.IssuedAt, 0).Format(time.UnixDate)
	}

	prettyTokenMap, err := json.MarshalIndent(tokenMap, "", "  ")
	if err != nil {
		log.Error("Failed token map rendering", zap.String("request_id", reqID), zap.String("error", err.Error()))
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(500)
		w.Write([]byte(`Internal Server Error`))
		return err
	}
	resp.Data["token"] = string(prettyTokenMap)

	content, err := uiFactory.Render("whoami", resp)
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
