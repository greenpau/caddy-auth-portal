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
	"os"
	"strings"

	jwt "github.com/greenpau/caddy-auth-jwt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	httpcaddyfile.RegisterDirective("auth_portal", parseCaddyfileAuthPortal)
}

func initLogger() *zap.Logger {
	logAtom := zap.NewAtomicLevel()
	logAtom.SetLevel(zapcore.DebugLevel)
	logEncoderConfig := zap.NewProductionEncoderConfig()
	logEncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	logEncoderConfig.TimeKey = "time"
	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(logEncoderConfig),
		zapcore.Lock(os.Stdout),
		logAtom,
	))
	return logger

}

// parseCaddyfileAuthPortal sets up an authentication portal. Syntax:
//
//     auth_portal {
//       path /auth
//       context <default|name>
//       backends {
//         local_backend {
//		     type <local>
//		     file <file_path>
//		     realm <name>
//	       }
//	     }
//	     jwt {
//	       token_name <value>
//	       token_secret <value>
//	       token_issuer <value>
//	     }
//	     ui {
//	       login_template <file_path>
//	       portal_template <file_path>
//	       logo_url <file_path|url_path>
//	       logo_description <value>
//	     }
//     }
//
func parseCaddyfileAuthPortal(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {

	logger := initLogger()
	backends := []string{}

	portal := AuthPortal{
		PrimaryInstance: true,
		Context:         "default",
		AuthURLPath:     "/auth",
		UserInterface: &UserInterfaceParameters{
			Templates: make(map[string]string),
		},
		TokenProvider: &jwt.TokenProviderConfig{},
		Backends:      []Backend{},
	}

	for h.Next() {
		for nesting := h.Nesting(); h.NextBlock(nesting); {
			rootDirective := h.Val()
			switch rootDirective {
			case "path":
				args := h.RemainingArgs()
				portal.AuthURLPath = args[0]
			case "context":
				args := h.RemainingArgs()
				portal.Context = args[0]
			case "backends":
				for nesting := h.Nesting(); h.NextBlock(nesting); {

					//logger.Debug("stage 3", zap.Any("root_directive", rootDirective), zap.Any("args", args))

					backendName := h.Val()
					backendProps := make(map[string]interface{})
					for subNesting := h.Nesting(); h.NextBlock(subNesting); {
						// panic(spew.Sdump(h))
						//return nil, h.Errf("xxx: %v", spew.Sdump(h))
						backendArg := h.Val()
						// args := h.RemainingArgs()
						// backendArg := args[1]
						switch backendArg {
						case "type", "file", "realm":
							if !h.NextArg() {
								return nil, h.Errf("auth backend %s subdirective %s has no value", backendName, backendArg)
							}
							logger.Debug("stage 3", zap.Any("root_directive", rootDirective), zap.Any("backendArg", backendArg), zap.Any("args", h.Val()))
							backendProps[backendArg] = h.Val()
						default:
							return nil, h.Errf("unknown auth backend %s subdirective: %s", backendName, backendArg)
						}
					}

					backendJSON, err := json.Marshal(backendProps)
					if err != nil {
						return nil, h.Errf("auth backend %s subdirective failed to compile to JSON: %s", backendName, err.Error())
					}
					backends = append(backends, string(backendJSON))
				}
			case "jwt":
				for nesting := h.Nesting(); h.NextBlock(nesting); {
					subDirective := h.Val()
					switch subDirective {
					case "token_name":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						portal.TokenProvider.TokenName = h.Val()
					case "token_secret":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						portal.TokenProvider.TokenSecret = h.Val()
					case "token_issuer":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						portal.TokenProvider.TokenIssuer = h.Val()
					default:
						return nil, h.Errf("unknown subdirective for %s: %s", rootDirective, subDirective)
					}
				}
			case "ui":
				for nesting := h.Nesting(); h.NextBlock(nesting); {
					subDirective := h.Val()
					if strings.HasSuffix(subDirective, "_template") {
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						templateName := strings.TrimRight(subDirective, "_template")
						portal.UserInterface.Templates[templateName] = h.Val()
						logger.Debug("stage 3", zap.Any("root_directive", rootDirective), zap.Any("subDirective", subDirective), zap.Any("args", h.Val()))
					} else {
						switch subDirective {
						case "logo_url":
							if !h.NextArg() {
								return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
							}
							portal.UserInterface.LogoURL = h.Val()
						case "logo_description":
							if !h.NextArg() {
								return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
							}
							portal.UserInterface.LogoDescription = h.Val()
						case "auto_redirect_url":
							if !h.NextArg() {
								return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
							}
							portal.UserInterface.AutoRedirectURL = h.Val()
						default:
							return nil, h.Errf("unsupported subdirective for %s: %s", rootDirective, subDirective)
						}
					}
				}
			default:
				return nil, h.Errf("unsupported root directive: %s", rootDirective)
			}
		}
	}

	if portal.AuthURLPath == "" {
		portal.AuthURLPath = "/auth"
	}
	if strings.HasSuffix(portal.AuthURLPath, "*") {
		return nil, h.Errf("path directive must not end with '*', got %s", portal.AuthURLPath)
	}
	if !strings.HasPrefix(portal.AuthURLPath, "/") {
		return nil, h.Errf("path directive must begin with '/', got %s", portal.AuthURLPath)
	}

	if portal.Context == "" {
		return nil, h.Errf("context directive must not be empty")
	}

	h.Reset()
	h.Next()
	pathMatcher := caddy.ModuleMap{
		"path": h.JSON(caddyhttp.MatchPath{portal.AuthURLPath + "*"}),
	}
	route := caddyhttp.Route{
		HandlersRaw: []json.RawMessage{caddyconfig.JSONModuleObject(portal, "handler", "auth_portal", nil)},
	}
	subroute := new(caddyhttp.Subroute)
	subroute.Routes = append([]caddyhttp.Route{route}, subroute.Routes...)
	return h.NewRoute(pathMatcher, subroute), nil
}
