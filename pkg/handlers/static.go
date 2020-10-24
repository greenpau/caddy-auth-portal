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
	"io"
	"net/http"
	"strings"
)

// ServeStaticAssets serves static pages.
func ServeStaticAssets(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	reqID := opts["request_id"].(string)
	log := opts["logger"].(*zap.Logger)
	urlPath := opts["url_path"].(string)

	if strings.HasPrefix(urlPath, "favicon") {
		urlPath = "assets/images/" + urlPath
	}

	asset, err := ui.StaticAssets.GetAsset(urlPath)
	if err != nil {
		log.Warn(
			"detected content not found",
			zap.String("request_id", reqID),
			zap.String("request_uri", urlPath),
		)
		http.Error(w, "404 not found", http.StatusNotFound)
		return nil
	}

	w.Header().Set("Content-Type", asset.ContentType)
	w.Header().Set("Etag", asset.Checksum)
	w.Header().Set("Cache-Control", "max-age=7200")

	if match := r.Header.Get("If-None-Match"); match != "" {
		if strings.Contains(match, asset.Checksum) {
			w.WriteHeader(http.StatusNotModified)
			return nil
		}
	}

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, asset.Content)
	return nil
}
