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
	"bytes"
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
	var primaryInstance bool = true
	var instanceContext string = "default"
	var authURLPath string = "/auth"
	var userInterface *UserInterfaceParameters
	var tokenProvider *jwt.TokenProviderConfig
	backends := []string{}

	for h.Next() {
		logger.Debug("stage 1")
		for nesting := h.Nesting(); h.NextBlock(nesting); {
			logger.Debug("stage 2 ")
			logger.Debug("stage 2", zap.Any("val", h.Val()))
			rootDirective := h.Val()
			switch rootDirective {
			case "path":
				args := h.RemainingArgs()
				authURLPath = args[0]
				logger.Debug("stage 2", zap.Any("root_directive", rootDirective), zap.Any("args", args))
				logger.Debug("stage 2", zap.Any("root_directive", rootDirective), zap.Any("authURLPath", authURLPath))

			case "context":
				args := h.RemainingArgs()
				instanceContext = args[0]
				logger.Debug("stage 2", zap.Any("root_directive", rootDirective), zap.Any("args", args))
				logger.Debug("stage 2", zap.Any("root_directive", rootDirective), zap.Any("instanceContext", authURLPath))
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
				if tokenProvider == nil {
					tokenProvider = &jwt.TokenProviderConfig{}
				}
				for nesting := h.Nesting(); h.NextBlock(nesting); {
					subDirective := h.Val()
					switch subDirective {
					case "token_name":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						tokenProvider.TokenName = h.Val()
						logger.Debug("stage 3", zap.Any("root_directive", rootDirective), zap.Any("subDirective", subDirective), zap.Any("args", tokenProvider.TokenName))
					case "token_secret":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						tokenProvider.TokenSecret = h.Val()
						logger.Debug("stage 3", zap.Any("root_directive", rootDirective), zap.Any("subDirective", subDirective), zap.Any("args", tokenProvider.TokenSecret))

					case "token_issuer":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						tokenProvider.TokenIssuer = h.Val()
						logger.Debug("stage 3", zap.Any("root_directive", rootDirective), zap.Any("subDirective", subDirective), zap.Any("args", tokenProvider.TokenIssuer))

					default:
						return nil, h.Errf("unknown subdirective for %s: %s", rootDirective, subDirective)
					}
				}
			case "ui":
				if userInterface == nil {
					userInterface = &UserInterfaceParameters{
						Templates: make(map[string]string),
					}
				}
				for nesting := h.Nesting(); h.NextBlock(nesting); {
					subDirective := h.Val()
					if strings.HasSuffix(subDirective, "_template") {
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						templateName := strings.TrimRight(subDirective, "_template")
						userInterface.Templates[templateName] = h.Val()
						logger.Debug("stage 3", zap.Any("root_directive", rootDirective), zap.Any("subDirective", subDirective), zap.Any("args", h.Val()))

					} else {
						switch subDirective {
						case "logo_url":
							if !h.NextArg() {
								return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
							}
							userInterface.LogoURL = h.Val()
							logger.Debug("stage 3", zap.Any("root_directive", rootDirective), zap.Any("subDirective", subDirective), zap.Any("args", h.Val()))

						case "logo_description":
							if !h.NextArg() {
								return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
							}
							userInterface.LogoDescription = h.Val()
							logger.Debug("stage 3", zap.Any("root_directive", rootDirective), zap.Any("subDirective", subDirective), zap.Any("args", h.Val()))

						case "auto_redirect_url":
							if !h.NextArg() {
								return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
							}
							userInterface.AutoRedirectURL = h.Val()
							logger.Debug("stage 3", zap.Any("root_directive", rootDirective), zap.Any("subDirective", subDirective), zap.Any("args", h.Val()))

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

	if authURLPath == "" {
		authURLPath = "/auth"
	}
	if strings.HasSuffix(authURLPath, "*") {
		return nil, h.Errf("path directive must not end with '*', got %s", authURLPath)
	}
	if !strings.HasPrefix(authURLPath, "/") {
		return nil, h.Errf("path directive must begin with '/', got %s", authURLPath)
	}

	if instanceContext == "" {
		return nil, h.Errf("context directive must not be empty")
	}

	logger.Debug("stage 4")

	/*
		if !h.Next() {
			return nil, h.ArgErr()
		}
	*/

	logger.Debug("stage 5")

	/*
		if !h.NextArg() {
			return nil, h.ArgErr()
		}
	*/

	logger.Debug("stage 6")

	// the ParseSegmentAsSubroute function expects the cursor
	// to be at the token just before the block opening,
	// so we need to rewind because we already read past it
	h.Reset()

	logger.Debug("stage 7")

	h.Next()

	logger.Debug("stage 8")

	// parse the block contents as a subroute handler
	/*
		handler, err := httpcaddyfile.ParseSegmentAsSubroute(h)
		if err != nil {

			logger.Debug("error @ stage 9")
			return nil, err
		}
	*/

	logger.Debug("stage 9")

	subroute := new(caddyhttp.Subroute)

	/*
		subroute, ok := handler.(*caddyhttp.Subroute)
		if !ok {
			return nil, h.Errf("segment was not parsed as a subroute")
		}
	*/

	logger.Debug("stage 10")

	// make a matcher on the path and everything below it
	pathMatcher := caddy.ModuleMap{
		"path": h.JSON(caddyhttp.MatchPath{authURLPath + "*"}),
	}

	var buffer bytes.Buffer
	buffer.WriteString("[{")
	buffer.WriteString("\"handler\":\"authentication\",")
	buffer.WriteString("\"providers\":{")
	buffer.WriteString("\"portal\":{")
	if primaryInstance {
		buffer.WriteString("\"primary\":true,")
	} else {
		buffer.WriteString("\"primary\":false,")
	}
	buffer.WriteString("\"context\":\"" + instanceContext + "\",")

	if userInterface != nil {
		userInterfaceJSON, err := json.Marshal(userInterface)
		if err != nil {
			return nil, h.Errf("auth backend ui subdirective failed to compile to JSON: %s", err.Error())
		}
		buffer.WriteString("\"ui\":{" + string(userInterfaceJSON) + "},")
	}

	if tokenProvider != nil {
		tokenProviderJSON, err := json.Marshal(tokenProvider)
		if err != nil {
			return nil, h.Errf("auth backend jwt subdirective failed to compile to JSON: %s", err.Error())
		}
		buffer.WriteString("\"jwt\":{" + string(tokenProviderJSON) + "},")
	}

	if len(backends) > 0 {
		buffer.WriteString("\"backends\":[")
		buffer.WriteString("],")
	}

	buffer.WriteString("\"auth_url_path\":\"" + authURLPath + "\"")
	buffer.WriteString("}}}]")

	//var buf string
	// buf = buffer.String()

	// panic(spew.Sdump(buffer.String()))

	// return nil, fmt.Errorf(spew.Sdump(buf))

	// build a route with a rewrite handler to strip the path prefix
	route := caddyhttp.Route{
		//HandlersRaw: []json.RawMessage{buffer.Bytes()},
		HandlersRaw: []json.RawMessage{caddyconfig.JSONModuleObject(buffer.Bytes(), "handler", "authentication", nil)},
	}

	// prepend the route to the subroute
	subroute.Routes = append([]caddyhttp.Route{route}, subroute.Routes...)

	// build and return a route from the subroute
	return h.NewRoute(pathMatcher, subroute), nil
}
