// Copyright 2020 Paul Greenberg @greenpau
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

package portal

import (
	"encoding/json"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"strings"
)

func init() {
	httpcaddyfile.RegisterDirective("auth_portal", parseCaddyfileAuthPortal)
}

// parseCaddyfileAuthPortal sets up an authentication portal. Syntax:
//
//     auth_portal /auth* {
//         <directives...>
//     }
//
func parseCaddyfileAuthPortal(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	if !h.Next() {
		return nil, h.ArgErr()
	}
	if !h.NextArg() {
		return nil, h.ArgErr()
	}

	// read the prefix to strip
	path := h.Val()
	if !strings.HasPrefix(path, "/") {
		return nil, h.Errf("path matcher must begin with '/', got %s", path)
	}

	// the ParseSegmentAsSubroute function expects the cursor
	// to be at the token just before the block opening,
	// so we need to rewind because we already read past it
	h.Reset()
	h.Next()

	// parse the block contents as a subroute handler
	handler, err := httpcaddyfile.ParseSegmentAsSubroute(h)
	if err != nil {
		return nil, err
	}
	subroute, ok := handler.(*caddyhttp.Subroute)
	if !ok {
		return nil, h.Errf("segment was not parsed as a subroute")
	}

	// make a matcher on the path and everything below it
	pathMatcher := caddy.ModuleMap{
		"path": h.JSON(caddyhttp.MatchPath{path}),
	}

	// build a route with a rewrite handler to strip the path prefix
	route := caddyhttp.Route{
		HandlersRaw: []json.RawMessage{
			caddyconfig.JSONModuleObject(AuthProvider{}, "handler", "authentication", nil),
		},
	}

	// prepend the route to the subroute
	subroute.Routes = append([]caddyhttp.Route{route}, subroute.Routes...)

	// build and return a route from the subroute
	return h.NewRoute(pathMatcher, subroute), nil
}
