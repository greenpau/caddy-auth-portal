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
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"

	jwtconfig "github.com/greenpau/caddy-auth-jwt/pkg/config"

	"github.com/greenpau/caddy-auth-portal/pkg/backends"
	"github.com/greenpau/caddy-auth-portal/pkg/cookies"
	"github.com/greenpau/caddy-auth-portal/pkg/core"
	"github.com/greenpau/caddy-auth-portal/pkg/registration"
	"github.com/greenpau/caddy-auth-portal/pkg/ui"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterDirective("auth_portal", parseCaddyfileAuthPortal)
}

// parseCaddyfileAuthPortal sets up an authentication portal. Syntax:
//
//     auth_portal {
//       path /auth
//       context <default|name>
//       backends {
//         local_backend {
//		     method <local>
//		     file <file_path>
//		     realm <name>
//	       }
//	     }
//
//       local_backend <file/path/to/user/db> <realm/name>
//
//	     jwt {
//	       token_name <value>
//	       token_secret <value>
//         token_lifetime <seconds>
//         token_sign_method <HS256|HS384|HS512|RS256|RS384|RS512>
//	     }
//	     ui {
//	       login_template <file_path>
//	       portal_template <file_path>
//	       logo_url <file_path|url_path>
//	       logo_description <value>
//         custom_css_path <path}url>
//	     }
//
//       cookie_domain <name>
//       cookie_path <name>
//
//       registration {
//         disabled <on|off>
//         title "User Registration"
//         code "NY2020"
//         dropbox <file/path/to/registration/dir/>
//         require accept_terms
//       }
//
//     }
//
func parseCaddyfileAuthPortal(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	portal := core.AuthPortal{
		PrimaryInstance: true,
		Context:         "default",
		AuthURLPath:     "/auth",
		UserInterface: &ui.UserInterfaceParameters{
			Templates: make(map[string]string),
		},
		UserRegistration: &registration.Registration{},
		Cookies:          &cookies.Cookies{},
		Backends:         []backends.Backend{},
	}

	// logger := utils.NewLogger()

	for h.Next() {
		args := h.RemainingArgs()
		if len(args) > 0 {
			return nil, h.Errf("auth backend supports only nested args: %v", args)
		}
		for nesting := h.Nesting(); h.NextBlock(nesting); {
			rootDirective := h.Val()
			switch rootDirective {
			case "cookie_domain":
				args := h.RemainingArgs()
				portal.Cookies.Domain = args[0]
			case "cookie_path":
				args := h.RemainingArgs()
				portal.Cookies.Path = args[0]
			case "path":
				args := h.RemainingArgs()
				portal.AuthURLPath = args[0]
			case "context":
				args := h.RemainingArgs()
				portal.Context = args[0]
			case "local_backend":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.Errf("auth backend %s directive has no value", rootDirective)
				}
				backendProps := make(map[string]interface{})
				backendProps["name"] = "local_backend"
				backendProps["method"] = "local"
				backendProps["path"] = args[0]
				if len(args) > 1 {
					backendProps["realm"] = args[1]
				} else {
					backendProps["realm"] = "local"
				}
				backendJSON, err := json.Marshal(backendProps)
				if err != nil {
					return nil, h.Errf("auth backend %s directive failed to compile to JSON: %s", rootDirective, err.Error())
				}
				backend := backends.Backend{}
				if err := backend.UnmarshalJSON(backendJSON); err != nil {
					return nil, h.Errf("auth backend %s directive failed to compile to JSON: %s", rootDirective, err.Error())
				}
				portal.Backends = append(portal.Backends, backend)
			case "backends":
				for nesting := h.Nesting(); h.NextBlock(nesting); {
					backendName := h.Val()
					backendProps := make(map[string]interface{})
					backendProps["name"] = backendName
					backendDisabled := false
					var backendAuthMethod string
					for subNesting := h.Nesting(); h.NextBlock(subNesting); {
						backendArg := h.Val()
						switch backendArg {
						case "method", "type":
							if !h.NextArg() {
								return nil, h.Errf("auth backend %s subdirective %s has no value", backendName, backendArg)
							}
							backendAuthMethod = h.Val()
							backendProps["method"] = backendAuthMethod
						case "trusted_authority":
							if !h.NextArg() {
								return nil, h.Errf("auth backend %s subdirective %s has no value", backendName, backendArg)
							}
							var trustedAuthorities []string
							if v, exists := backendProps["trusted_authorities"]; exists {
								trustedAuthorities = v.([]string)
							}
							trustedAuthorities = append(trustedAuthorities, h.Val())
							backendProps["trusted_authorities"] = trustedAuthorities
						case "user":
							userArgs := h.RemainingArgs()
							if len(userArgs) < 4 {
								return nil, h.Errf("auth backend %s subdirective %s is missing arguments", backendName, backendArg)
							}
							var userRoles []string
							var userEmail string
							var userMatchType string
							var ptr int
							// Get email address pattern
							if userArgs[ptr] == "" {
								return nil, h.Errf("auth backend %s subdirective %s is malformed, empty email", backendName, backendArg)
							}
							userEmail = userArgs[ptr]
							ptr++
							// Search for the indicator of whether it is exact or regex match
							switch userArgs[ptr] {
							case "regex":
								userMatchType = userArgs[ptr]
								if _, err := regexp.Compile(userEmail); err != nil {
									return nil, h.Errf(
										"auth backend %s subdirective %s is malformed, failed to compile regex: %s",
										backendName, backendArg, err,
									)
								}
								ptr++
							case "exact":
								userMatchType = userArgs[ptr]
								ptr++
							default:
								userMatchType = "exact"
							}

							// Next, search for add argument
							if userArgs[ptr] != "add" {
								return nil, h.Errf(
									"auth backend %s subdirective %s is malformed: add (expected) vs %s (received)",
									backendName, backendArg, userArgs[ptr],
								)
							}
							ptr++
							// Next, the only supported values are role and roles
							switch userArgs[ptr] {
							case "role", "roles":
								ptr++
							default:
								return nil, h.Errf(
									"auth backend %s subdirective %s is malformed: role/roles (expected) vs %s (received)",
									backendName, backendArg, userArgs[2],
								)
							}
							if ptr >= len(userArgs) {
								return nil, h.Errf(
									"auth backend %s subdirective %s is malformed, not enough arguments: %v",
									backendName, backendArg, userArgs,
								)
							}
							userRoles = userArgs[ptr:]
							// Finally, amend the existing mapping
							if _, exists := backendProps["user_roles"]; !exists {
								backendProps["user_roles"] = make([]map[string]interface{}, 1, 1)
							}
							userRoleMap := make(map[string]interface{})
							userRoleMap["email"] = userEmail
							userRoleMap["match"] = userMatchType
							userRoleMap["roles"] = userRoles
							userRoleMaps := backendProps["user_roles"].([]map[string]interface{})
							userRoleMaps = append(userRoleMaps, userRoleMap)
							backendProps["user_roles"] = userRoleMaps
						case "disabled":
							backendDisabled = true
							break
						case "username", "password", "search_base_dn", "search_filter", "path", "realm":
							if !h.NextArg() {
								return nil, h.Errf("auth backend %s subdirective %s has no value", backendName, backendArg)
							}
							backendProps[backendArg] = h.Val()
						case "attributes":
							attrMap := make(map[string]interface{})
							for attrNesting := h.Nesting(); h.NextBlock(attrNesting); {
								attrName := h.Val()
								if !h.NextArg() {
									return nil, h.Errf("auth backend %s subdirective %s key %s has no value", backendName, backendArg, attrName)
								}
								attrMap[attrName] = h.Val()
							}
							backendProps[backendArg] = attrMap
						case "servers":
							serverMaps := []map[string]interface{}{}
							for serverNesting := h.Nesting(); h.NextBlock(serverNesting); {
								serverMap := make(map[string]interface{})
								serverMap["addr"] = h.Val()
								serverProps := h.RemainingArgs()
								if len(serverProps) > 0 {
									for _, serverProp := range serverProps {
										switch serverProp {
										case "ignore_cert_errors":
											serverMap[serverProp] = true
										default:
											return nil, h.Errf("auth backend %s subdirective %s prop %s is unsupported", backendName, backendArg, serverProp)
										}
									}
								}
								serverMaps = append(serverMaps, serverMap)
							}
							backendProps[backendArg] = serverMaps
						case "groups":
							groupMaps := []map[string]interface{}{}
							for groupNesting := h.Nesting(); h.NextBlock(groupNesting); {
								groupMap := make(map[string]interface{})
								groupDN := h.Val()
								groupMap["dn"] = groupDN
								groupRoles := h.RemainingArgs()
								if len(groupRoles) == 0 {
									return nil, h.Errf("auth backend %s subdirective %s dn %s has no roles", backendName, backendArg, groupDN)
								}
								groupMap["roles"] = groupRoles
								groupMaps = append(groupMaps, groupMap)
							}
							backendProps[backendArg] = groupMaps
						case "provider":
							if !h.NextArg() {
								return nil, h.Errf("auth backend %s subdirective %s has no value", backendName, backendArg)
							}
							backendProps[backendArg] = h.Val()
						case "idp_metadata_location", "idp_sign_cert_location", "tenant_id",
							"application_id", "application_name", "entity_id", "domain_name",
							"client_id", "client_secret", "server_id", "base_auth_url", "metadata_url",
							"identity_token_name":
							if !h.NextArg() {
								return nil, h.Errf("auth backend %s subdirective %s has no value", backendName, backendArg)
							}
							backendProps[backendArg] = h.Val()
						case "acs_url":
							if !h.NextArg() {
								return nil, h.Errf("auth backend %s subdirective %s has no value", backendName, backendArg)
							}
							var acsURLs []string
							if v, exists := backendProps["acs_urls"]; exists {
								acsURLs = v.([]string)
							}
							acsURLs = append(acsURLs, h.Val())
							backendProps["acs_urls"] = acsURLs
						case "scopes":
							backendProps["scopes"] = h.RemainingArgs()
						default:
							return nil, h.Errf("unknown auth backend %s subdirective: %s", backendName, backendArg)
						}
					}
					if !backendDisabled {
						backendJSON, err := json.Marshal(backendProps)
						if err != nil {
							return nil, h.Errf("auth backend %s subdirective failed to compile to JSON: %s", backendName, err.Error())
						}
						backend := &backends.Backend{}
						if err := backend.UnmarshalJSON(backendJSON); err != nil {
							return nil, h.Errf("auth backend %s subdirective failed to compile backend from JSON: %s", backendName, err.Error())
						}
						portal.Backends = append(portal.Backends, *backend)
					}
				}
			case "jwt_token_file", "jwt_token_rsa_file":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.Errf("auth backend %s directive has no value", rootDirective)
				}
				if len(args) != 2 {
					return nil, h.Errf("%s argument values are unsupported %v", rootDirective, args)
				}
				if portal.TokenProvider == nil {
					portal.TokenProvider = jwtconfig.NewCommonTokenConfig()
				}
				portal.TokenProvider.TokenRSAFiles = make(map[string]string)
				portal.TokenProvider.TokenRSAFiles[args[0]] = args[1]
			case "jwt_token_name":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.Errf("auth backend %s directive has no value", rootDirective)
				}
				if len(args) != 1 {
					return nil, h.Errf("%s argument values are unsupported %v", rootDirective, args)
				}
				if portal.TokenProvider == nil {
					portal.TokenProvider = jwtconfig.NewCommonTokenConfig()
				}
				portal.TokenProvider.TokenName = args[0]
			case "jwt_token_secret":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.Errf("auth backend %s directive has no value", rootDirective)
				}
				if len(args) != 1 {
					return nil, h.Errf("%s argument values are unsupported %v", rootDirective, args)
				}
				if portal.TokenProvider == nil {
					portal.TokenProvider = jwtconfig.NewCommonTokenConfig()
				}
				portal.TokenProvider.TokenSecret = args[0]
			case "jwt_token_sign_method":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.Errf("auth backend %s directive has no value", rootDirective)
				}
				if len(args) != 1 {
					return nil, h.Errf("%s argument values are unsupported %v", rootDirective, args)
				}
				if portal.TokenProvider == nil {
					portal.TokenProvider = jwtconfig.NewCommonTokenConfig()
				}
				portal.TokenProvider.TokenSignMethod = args[0]
			case "jwt_token_lifetime":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.Errf("auth backend %s directive has no value", rootDirective)
				}
				if len(args) != 1 {
					return nil, h.Errf("%s argument values are unsupported %v", rootDirective, args)
				}
				if portal.TokenProvider == nil {
					portal.TokenProvider = jwtconfig.NewCommonTokenConfig()
				}
				lifetime, err := strconv.Atoi(h.Val())
				if err != nil {
					return nil, h.Errf("%s argument value conversion failed: %s", rootDirective, err)
				}
				portal.TokenProvider.TokenLifetime = lifetime
			case "jwt":
				if portal.TokenProvider == nil {
					portal.TokenProvider = jwtconfig.NewCommonTokenConfig()
				}
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

					case "token_rsa_file":
						rsaArgs := h.RemainingArgs()
						if len(rsaArgs) != 2 {
							return nil, h.Errf("%s %s subdirective requires two arguments: key id and file path", rootDirective, subDirective)
						}
						portal.TokenProvider.TokenRSAFiles = make(map[string]string)
						portal.TokenProvider.TokenRSAFiles[rsaArgs[0]] = rsaArgs[1]
					case "token_lifetime":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						lifetime, err := strconv.Atoi(h.Val())
						if err != nil {
							return nil, h.Errf("%s %s subdirective value conversion failed: %s", rootDirective, subDirective, err)
						}
						portal.TokenProvider.TokenLifetime = lifetime
					case "token_sign_method":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						portal.TokenProvider.TokenSignMethod = h.Val()
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
						templateName := strings.TrimSuffix(subDirective, "_template")
						portal.UserInterface.Templates[templateName] = h.Val()
					} else {
						switch subDirective {
						case "theme":
							if !h.NextArg() {
								return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
							}
							portal.UserInterface.Theme = h.Val()
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
						case "password_recovery_enabled":
							if !h.NextArg() {
								return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
							}
							if h.Val() == "yes" || h.Val() == "true" {
								portal.UserInterface.PasswordRecoveryEnabled = true
							}
						case "links":
							for subNesting := h.Nesting(); h.NextBlock(subNesting); {
								title := h.Val()
								args := h.RemainingArgs()
								if len(args) == 0 {
									return nil, h.Errf("auth backend %s subdirective %s has no value", subDirective, title)
								}
								privateLink := ui.UserInterfaceLink{
									Title: title,
									Link:  args[0],
								}
								if len(args) == 1 {
									portal.UserInterface.PrivateLinks = append(portal.UserInterface.PrivateLinks, privateLink)
									continue
								}
								argp := 1
								disabledLink := false
								for argp < len(args) {
									switch args[argp] {
									case "target_blank":
										privateLink.Target = "_blank"
										privateLink.TargetEnabled = true
									case "icon":
										argp++
										if argp < len(args) {
											privateLink.IconName = args[argp]
											privateLink.IconEnabled = true
										}
									case "disabled":
										disabledLink = true
									default:
										return nil, h.Errf("auth backend %s subdirective %s has unsupported key %s", subDirective, title, args[argp])
									}
									argp++
								}
								if disabledLink {
									continue
								}
								portal.UserInterface.PrivateLinks = append(portal.UserInterface.PrivateLinks, privateLink)
							}
						case "custom_css", "custom_css_path":
							if !h.NextArg() {
								return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
							}
							portal.UserInterface.CustomCSSPath = h.Val()
						case "custom_js", "custom_js_path":
							if !h.NextArg() {
								return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
							}
							portal.UserInterface.CustomJsPath = h.Val()
						case "custom_html_header_path":
							if !h.NextArg() {
								return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
							}
							b, err := ioutil.ReadFile(h.Val())
							if err != nil {
								return nil, h.Errf("%s %s subdirective: %s %s", rootDirective, subDirective, h.Val(), err)
							}
							for k, v := range ui.PageTemplates {
								headIndex := strings.Index(v, "<meta name=\"description\"")
								if headIndex < 1 {
									continue
								}
								v = v[:headIndex] + string(b) + v[headIndex:]
								ui.PageTemplates[k] = v
							}
						default:
							return nil, h.Errf("unsupported subdirective for %s: %s", rootDirective, subDirective)
						}
					}
				}
			case "registration":
				for nesting := h.Nesting(); h.NextBlock(nesting); {
					subDirective := h.Val()
					switch subDirective {
					case "title":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						portal.UserRegistration.Title = h.Val()
					case "disabled":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						if h.Val() == "yes" || h.Val() == "on" {
							portal.UserRegistration.Disabled = true
						}
					case "code":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						portal.UserRegistration.Code = h.Val()
					case "dropbox":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						portal.UserRegistration.Dropbox = h.Val()
					case "require":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						requirement := h.Val()
						switch requirement {
						case "accept_terms":
							portal.UserRegistration.RequireAcceptTerms = true
						case "domain_mx":
							portal.UserRegistration.RequireDomainMailRecord = true
						default:
							return nil, h.Errf("unsupported requirement %s in %s %s", requirement, rootDirective, subDirective)
						}
					default:
						return nil, h.Errf("unsupported subdirective for %s: %s", rootDirective, subDirective)
					}
				}
			case "enable":
				args := strings.Join(h.RemainingArgs(), " ")
				switch args {
				case "source ip tracking":
					portal.EnableSourceIPTracking = true
				default:
					return nil, h.Errf("unsupported directive for %s: %s", rootDirective, args)
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

	if portal.TokenProvider == nil {
		portal.TokenProvider = jwtconfig.NewCommonTokenConfig()
		portal.TokenProvider.TokenSecret = utils.GetRandomStringFromRange(32, 64)
	}

	h.Reset()
	h.Next()
	pathMatcher := caddy.ModuleMap{
		"path": h.JSON(caddyhttp.MatchPath{portal.AuthURLPath + "*"}),
	}

	route := caddyhttp.Route{
		HandlersRaw: []json.RawMessage{
			caddyconfig.JSONModuleObject(
				AuthMiddleware{
					Portal: &portal,
				},
				"handler",
				"auth_portal",
				nil,
			),
		},
	}
	subroute := new(caddyhttp.Subroute)
	subroute.Routes = append([]caddyhttp.Route{route}, subroute.Routes...)
	return h.NewRoute(pathMatcher, subroute), nil
}
