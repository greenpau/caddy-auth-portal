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
	"github.com/greenpau/caddy-auth-portal/pkg/ui"
	"github.com/greenpau/go-identity/pkg/requests"
	"io"
	// "go.uber.org/zap"
	"net/http"
	"path"
	"strings"
)

func (p *Authenticator) handleHTTPStaticAssets(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	var assetPath string
	switch {
	case strings.Contains(r.URL.Path, "/favicon"):
		assetPath = "assets/images/" + path.Base(r.URL.Path)
	default:
		i := strings.Index(r.URL.Path, "/assets/")
		assetPath = r.URL.Path[i+1:]
	}

	p.logRequest("static assets", r, rr)
	asset, err := ui.StaticAssets.GetAsset(assetPath)
	if err != nil {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusNotFound)
	}

	if asset.Restricted && !rr.Response.Authenticated {
		// If an asset is a protected asset and a user is not authorized,
		// then deny access to the asset.
		return p.handleHTTPError(ctx, w, r, rr, http.StatusUnauthorized)
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
	// TODO(greenpau): add compressed output, e.g. bzip.
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, asset.Content)
	return nil
}
