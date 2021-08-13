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
	"encoding/base64"
	"fmt"
	"github.com/greenpau/go-identity/pkg/requests"
	"net/http"
	"strings"
)

func (p *Authenticator) handleHTTPBasicLogin(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	pathPrefix := "/basic/login/"
	p.disableClientCache(w)
	p.injectRedirectURL(ctx, w, r, rr)
	// The GET request arrives to `/basic/login/<realm>`.
	// Extract realm name and process as a regular login.
	i := strings.Index(r.URL.Path, pathPrefix)
	if i < 0 {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
	}
	realm := strings.TrimPrefix(r.URL.Path[i:], pathPrefix)
	credentials, err := parseBasicAuthHeader(r)
	w.Header().Set("Content-Type", "text/plain")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(http.StatusText(http.StatusBadRequest)))
		return nil
	}
	if credentials == nil {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", realm))
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Authorization Required"))
		return nil
	}
	if v, exists := credentials["realm"]; exists {
		realm = v
	} else {
		credentials["realm"] = realm
	}
	if realm == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(http.StatusText(http.StatusBadRequest)))
		return nil
	}
	if err := p.authenticateLoginRequest(ctx, w, r, rr, credentials); err != nil {
		return p.handleJSONErrorWithLog(ctx, w, r, rr, rr.Response.Code, err.Error())
	}
	if err := p.authorizeLoginRequest(ctx, w, r, rr); err != nil {
		return p.handleJSONErrorWithLog(ctx, w, r, rr, rr.Response.Code, err.Error())
	}
	w.WriteHeader(rr.Response.Code)
	return nil
}

func parseBasicAuthHeader(r *http.Request) (map[string]string, error) {
	kv := make(map[string]string)
	headers := strings.Split(r.Header.Get("Authorization"), ",")
	if len(headers) == 0 {
		return nil, nil
	}
	for _, header := range headers {
		header = strings.TrimSpace(header)
		switch {
		case strings.HasPrefix(header, "Basic") || strings.HasPrefix(header, "basic"):
			arr := strings.SplitN(header, " ", 2)
			if len(arr) != 2 {
				return nil, fmt.Errorf("invalid authorization header")
			}
			arrDecoded, err := base64.StdEncoding.DecodeString(arr[1])
			if err != nil {
				return nil, err
			}
			creds := strings.SplitN(string(arrDecoded), ":", 2)
			kv["username"] = creds[0]
			kv["password"] = creds[1]
		case strings.HasPrefix(header, "Realm") || strings.HasPrefix(header, "realm"):
			arr := strings.SplitN(header, "=", 2)
			if len(arr) != 2 {
				return nil, fmt.Errorf("invalid authorization header")
			}
			kv["realm"] = arr[1]
		}
	}
	if _, exists := kv["username"]; !exists {
		return nil, nil
	}
	return kv, nil
}
