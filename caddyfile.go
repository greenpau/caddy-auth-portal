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

package portal

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	// "regexp"
	"strconv"
	"strings"

	"github.com/greenpau/caddy-authorize/pkg/kms"
	"github.com/greenpau/caddy-authorize/pkg/options"

	"github.com/greenpau/caddy-auth-portal/pkg/authn"
	"github.com/greenpau/caddy-auth-portal/pkg/backends"
	"github.com/greenpau/caddy-auth-portal/pkg/cookie"
	"github.com/greenpau/caddy-auth-portal/pkg/registration"
	"github.com/greenpau/caddy-auth-portal/pkg/transformer"
	"github.com/greenpau/caddy-auth-portal/pkg/ui"
	cfgutils "github.com/greenpau/caddy-authorize/pkg/utils/cfg"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const badRepl string = "ERROR_BAD_REPL"

func init() {
	httpcaddyfile.RegisterDirective("authp", getRouteFromParseCaddyfileAuthenticator)
}

// parseCaddyfileAuthenticator sets up an authentication portal. Syntax:
//
//     authp {
//       context <default|name>
//       backends {
//         local_backend {
//		     method <local>
//		     file <file_path>
//		     realm <name>
//	       }
//
//         generic_oauth2_backend {
//           method oauth2
//           realm generic
//           provider generic
//           base_auth_url <base_url>
//           metadata_url <metadata_url>
//           client_id <client_id>
//           client_secret <client_secret>
//           scopes openid email profile
//           disable metadata_discovery
//           authorization_url <authorization_url>
//           disable key_verification
//         }
//
//         gitlab_backend {
//           method oauth2
//           realm gitlab
//           provider gitlab
//           domain_name <domain>
//           client_id <client_id>
//           client_secret <client_secret>
//           user_group_filters <regex_pattern>
//         }
//       }
//
//       backend local <file/path/to/user/db> <realm/name>
//       backend google <client_id> <client_secret>
//       backend github <client_id> <client_secret>
//       backend facebook <client_id> <client_secret>
//
//	     crypto key sign-verify <shared_secret>
//
//	     ui {
//	       template <login|portal> <file_path>
//	       logo_url <file_path|url_path>
//	       logo_description <value>
//         custom css path <path>
//         custom js path <path>
//         custom html header path <path>
//         static_asset <uri> <content_type> <path>
//         allow settings for role <role>
//	     }
//
//       cookie domain <name>
//       cookie path <name>
//       cookie lifetime <seconds>
//       cookie samesite <lax|strict|none>
//       cookie insecure <on|off>
//
//       registration {
//         disabled <on|off>
//         title "User Registration"
//         code "NY2020"
//         dropbox <file/path/to/registration/dir/>
//         require accept terms
//         require domain mx
//       }
//
//       validate source address
//     }
//
func parseCaddyfileAuthenticator(h httpcaddyfile.Helper) (*authn.Authenticator, error) {
	var cryptoKeyConfig, cryptoKeyStoreConfig []string
	var cryptoKeyConfigFound, cryptoKeyStoreConfigFound bool
	portal := authn.Authenticator{
		PrimaryInstance: true,
		Context:         "default",
		UI: &ui.Parameters{
			Templates: make(map[string]string),
		},
		UserRegistrationConfig: &registration.Config{},
		CookieConfig:           &cookie.Config{},
		TokenValidatorOptions:  &options.TokenValidatorOptions{},
		TokenGrantorOptions:    &options.TokenGrantorOptions{},
	}

	repl := caddy.NewReplacer()

	// logger := utils.NewLogger()

	for h.Next() {
		args := h.RemainingArgs()
		if len(args) > 0 {
			return nil, h.Errf("auth backend supports only nested args: %v", args)
		}
		for nesting := h.Nesting(); h.NextBlock(nesting); {
			rootDirective := h.Val()
			switch rootDirective {
			case "transform":
				args := strings.Join(h.RemainingArgs(), " ")
				switch args {
				case "user", "users":
					tc := &transformer.Config{}
					for nesting := h.Nesting(); h.NextBlock(nesting); {
						k := h.Val()
						trArgs := h.RemainingArgs()
						trArgs = append([]string{k}, trArgs...)
						encodedArgs := cfgutils.EncodeArgs(trArgs)
						var matchArgs bool
						for _, arg := range trArgs {
							if arg == "match" {
								matchArgs = true
								break
							}
						}
						if matchArgs {
							if trArgs[0] == "match" {
								trArgs = append([]string{"exact"}, trArgs...)
								encodedArgs = cfgutils.EncodeArgs(trArgs)
							}
							tc.Matchers = append(tc.Matchers, encodedArgs)
						} else {
							tc.Actions = append(tc.Actions, encodedArgs)
						}
					}
					portal.UserTransformerConfigs = append(portal.UserTransformerConfigs, tc)
				default:
					return nil, h.Errf("unsupported directive for %s: %s", rootDirective, args)
				}
			case "cookie":
				args := h.RemainingArgs()
				if len(args) != 2 {
					return nil, h.Errf("%s %s directive is invalid", rootDirective, strings.Join(args, " "))
				}
				switch args[0] {
				case "domain":
					portal.CookieConfig.Domain = args[1]
				case "path":
					portal.CookieConfig.Path = args[1]
				case "lifetime":
					lifetime, err := strconv.Atoi(args[1])
					if err != nil {
						return nil, h.Errf("%s %s value %q conversion failed: %v", rootDirective, args[0], args[1], err)
					}
					if lifetime < 1 {
						return nil, h.Errf("%s %s value must be greater than zero", rootDirective, args[0])
					}
					portal.CookieConfig.Lifetime = lifetime
				case "samesite":
					portal.CookieConfig.SameSite = args[1]
				case "insecure":
					enabled, err := cfgutils.ParseBoolArg(args[1])
					if err != nil {
						return nil, h.Errf("%s %s directive value of %q is invalid: %v", rootDirective, args[0], args[1], err)
					}
					portal.CookieConfig.Insecure = enabled
				default:
					return nil, h.Errf("%s %s directive is unsupported", rootDirective, strings.Join(args, " "))
				}
			case "crypto":
				args := h.RemainingArgs()
				if len(args) < 3 {
					return nil, h.Errf("%s directive %q is too short", rootDirective, strings.Join(args, " "))
				}
				encodedArgs := cfgutils.EncodeArgs(args)
				encodedArgs = repl.ReplaceAll(encodedArgs, badRepl)
				cryptoKeyConfig = append(cryptoKeyConfig, encodedArgs)
				switch args[0] {
				case "key":
					cryptoKeyConfigFound = true
				case "default":
					cryptoKeyStoreConfig = append(cryptoKeyStoreConfig, encodedArgs)
					cryptoKeyStoreConfigFound = true
				default:
					return nil, h.Errf("%s directive value of %q is unsupported", rootDirective, strings.Join(args, " "))
				}
			case "context":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.Errf("auth backend %s directive has no value", rootDirective)
				}
				portal.Context = args[0]
			case "backend":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.Errf("auth backend %s directive has no value", rootDirective)
				}
				if args[len(args)-1] == "disabled" {
					break
				}
				cfg := make(map[string]interface{})
				switch args[0] {
				case "local":
					if len(args) != 3 {
						return nil, h.Errf("authp directive is invalid: backend %s", cfgutils.EncodeArgs(args))
					}
					cfg["name"] = fmt.Sprintf("local_backend_%d", len(portal.BackendConfigs))
					cfg["method"] = "local"
					cfg["path"] = args[1]
					cfg["realm"] = args[2]
				case "google":
					if len(args) != 3 {
						return nil, h.Errf("authp directive is invalid: backend %s", cfgutils.EncodeArgs(args))
					}
					cfg["name"] = fmt.Sprintf("google_backend_%d", len(portal.BackendConfigs))
					cfg["method"] = "oauth2"
					cfg["realm"] = "google"
					cfg["provider"] = "google"
					cfg["client_id"] = repl.ReplaceAll(args[1], badRepl)
					cfg["client_secret"] = repl.ReplaceAll(args[2], badRepl)
					cfg["scopes"] = []string{"openid", "email", "profile"}
				case "github":
					if len(args) != 3 {
						return nil, h.Errf("authp directive is invalid: backend %s", cfgutils.EncodeArgs(args))
					}
					cfg["name"] = fmt.Sprintf("github_backend_%d", len(portal.BackendConfigs))
					cfg["method"] = "oauth2"
					cfg["realm"] = "github"
					cfg["provider"] = "github"
					cfg["client_id"] = repl.ReplaceAll(args[1], badRepl)
					cfg["client_secret"] = repl.ReplaceAll(args[2], badRepl)
					cfg["scopes"] = []string{"user"}
				case "facebook":
					if len(args) != 3 {
						return nil, h.Errf("authp directive is invalid: backend %s", cfgutils.EncodeArgs(args))
					}
					cfg["name"] = fmt.Sprintf("facebook_backend_%d", len(portal.BackendConfigs))
					cfg["method"] = "oauth2"
					cfg["realm"] = "facebook"
					cfg["provider"] = "facebook"
					cfg["client_id"] = repl.ReplaceAll(args[1], badRepl)
					cfg["client_secret"] = repl.ReplaceAll(args[2], badRepl)
					cfg["scopes"] = []string{"email"}
				default:
					return nil, h.Errf("auth backend directive is invalid: backend %v", args)
				}
				backendConfig, err := backends.NewConfig(cfg)
				if err != nil {
					return nil, h.Errf("auth backend %s directive failed: %v", rootDirective, err.Error())
				}
				portal.BackendConfigs = append(portal.BackendConfigs, *backendConfig)
			case "backends":
				for nesting := h.Nesting(); h.NextBlock(nesting); {
					backendName := h.Val()
					cfg := make(map[string]interface{})
					cfg["name"] = backendName
					backendDisabled := false
					var backendAuthMethod string
					for subNesting := h.Nesting(); h.NextBlock(subNesting); {
						backendArg := h.Val()
						switch backendArg {
						case "method", "type":
							if !h.NextArg() {
								return backendValueErr(h, backendName, backendArg)
							}
							backendAuthMethod = h.Val()
							cfg["method"] = backendAuthMethod
						case "trusted_authority":
							if !h.NextArg() {
								return backendValueErr(h, backendName, backendArg)
							}
							var trustedAuthorities []string
							if v, exists := cfg["trusted_authorities"]; exists {
								trustedAuthorities = v.([]string)
							}
							trustedAuthorities = append(trustedAuthorities, h.Val())
							cfg["trusted_authorities"] = trustedAuthorities
						case "disabled":
							backendDisabled = true
							break
						case "username", "password", "search_base_dn", "search_group_filter", "path", "realm":
							if !h.NextArg() {
								return backendValueErr(h, backendName, backendArg)
							}
							cfg[backendArg] = repl.ReplaceAll(h.Val(), badRepl)
						case "search_filter", "search_user_filter":
							if !h.NextArg() {
								return backendValueErr(h, backendName, backendArg)
							}
							cfg["search_user_filter"] = repl.ReplaceAll(h.Val(), badRepl)
						case "attributes":
							attrMap := make(map[string]interface{})
							for attrNesting := h.Nesting(); h.NextBlock(attrNesting); {
								attrName := h.Val()
								if !h.NextArg() {
									return backendPropErr(h, backendName, backendArg, attrName, "has no value")
								}
								attrMap[attrName] = h.Val()
							}
							cfg[backendArg] = attrMap
						case "servers":
							serverMaps := []map[string]interface{}{}
							for serverNesting := h.Nesting(); h.NextBlock(serverNesting); {
								serverMap := make(map[string]interface{})
								serverMap["addr"] = h.Val()
								serverProps := h.RemainingArgs()
								if len(serverProps) > 0 {
									for _, serverProp := range serverProps {
										switch serverProp {
										case "ignore_cert_errors", "posix_groups":
											serverMap[serverProp] = true
										default:
											return backendPropErr(h, backendName, backendArg, serverProp, "is unsupported")
										}
									}
								}
								serverMaps = append(serverMaps, serverMap)
							}
							cfg[backendArg] = serverMaps
						case "groups":
							groupMaps := []map[string]interface{}{}
							for groupNesting := h.Nesting(); h.NextBlock(groupNesting); {
								groupMap := make(map[string]interface{})
								groupDN := h.Val()
								groupMap["dn"] = groupDN
								groupRoles := h.RemainingArgs()
								if len(groupRoles) == 0 {
									return backendPropErr(h, backendName, backendArg, groupDN, "has no roles")
								}
								groupMap["roles"] = groupRoles
								groupMaps = append(groupMaps, groupMap)
							}
							cfg[backendArg] = groupMaps
						case "provider":
							if !h.NextArg() {
								return backendValueErr(h, backendName, backendArg)
							}
							cfg[backendArg] = h.Val()
						case "idp_metadata_location", "idp_sign_cert_location", "tenant_id",
							"application_id", "application_name", "entity_id", "domain_name",
							"client_id", "client_secret", "server_id", "base_auth_url", "metadata_url",
							"identity_token_name", "authorization_url", "token_url":
							if !h.NextArg() {
								return backendValueErr(h, backendName, backendArg)
							}
							cfg[backendArg] = repl.ReplaceAll(h.Val(), badRepl)
						case "acs_url":
							if !h.NextArg() {
								return backendValueErr(h, backendName, backendArg)
							}
							var acsURLs []string
							if v, exists := cfg["acs_urls"]; exists {
								acsURLs = v.([]string)
							}
							acsURLs = append(acsURLs, h.Val())
							cfg["acs_urls"] = acsURLs
						case "scopes", "user_group_filters", "user_org_filters":
							if _, exists := cfg[backendArg]; exists {
								values := cfg[backendArg].([]string)
								values = append(values, h.RemainingArgs()...)
								cfg[backendArg] = values
							} else {
								cfg[backendArg] = h.RemainingArgs()
							}
						case "delay_start", "retry_attempts", "retry_interval":
							backendVal := strings.Join(h.RemainingArgs(), "|")
							i, err := strconv.Atoi(backendVal)
							if err != nil {
								return backendValueConversionErr(h, backendName, backendArg, backendVal, err)
							}
							cfg[backendArg] = i
						case "disable":
							backendVal := strings.Join(h.RemainingArgs(), "_")
							switch backendVal {
							case "metadata_discovery":
							case "key_verification":
							case "pass_grant_type":
							case "response_type":
							case "nonce":
							default:
								return backendPropErr(h, backendName, backendArg, backendVal, "is unsupported")
							}
							cfg[backendVal+"_disabled"] = true
						case "enable":
							backendVal := strings.Join(h.RemainingArgs(), "_")
							switch backendVal {
							case "accept_header":
							default:
								return backendPropErr(h, backendName, backendArg, backendVal, "is unsupported")
							}
							cfg[backendVal+"_enabled"] = true
						default:
							return backendUnsupportedValueErr(h, backendName, backendArg)
						}
					}
					if !backendDisabled {
						backendConfig, err := backends.NewConfig(cfg)
						if err != nil {
							return nil, h.Errf("auth backend %s directive failed: %v", rootDirective, err.Error())
						}
						portal.BackendConfigs = append(portal.BackendConfigs, *backendConfig)
					}
				}
			case "ui":
				for nesting := h.Nesting(); h.NextBlock(nesting); {
					subDirective := h.Val()
					switch subDirective {
					case "template":
						hargs := h.RemainingArgs()
						switch {
						case len(hargs) == 2:
							portal.UI.Templates[hargs[0]] = hargs[1]
						default:
							args := strings.Join(h.RemainingArgs(), " ")
							return nil, h.Errf("%s directive %q is invalid", rootDirective, args)
						}
					case "theme":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						portal.UI.Theme = h.Val()
					case "logo":
						args := strings.Join(h.RemainingArgs(), " ")
						args = strings.TrimSpace(args)
						switch {
						case strings.HasPrefix(args, "url"):
							portal.UI.LogoURL = strings.ReplaceAll(args, "url ", "")
						case strings.HasPrefix(args, "description"):
							portal.UI.LogoDescription = strings.ReplaceAll(args, "description ", "")
						case args == "":
							return nil, h.Errf("%s %s directive has no value", rootDirective, subDirective)
						default:
							return nil, h.Errf("%s directive %q is unsupported", rootDirective, args)
						}
					case "auto_redirect_url":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						portal.UI.AutoRedirectURL = h.Val()
					case "password_recovery_enabled":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						if h.Val() == "yes" || h.Val() == "true" {
							portal.UI.PasswordRecoveryEnabled = true
						}
					case "links":
						for subNesting := h.Nesting(); h.NextBlock(subNesting); {
							title := h.Val()
							args := h.RemainingArgs()
							if len(args) == 0 {
								return nil, h.Errf("auth backend %s subdirective %s has no value", subDirective, title)
							}
							privateLink := ui.Link{
								Title: title,
								Link:  args[0],
							}
							if len(args) == 1 {
								portal.UI.PrivateLinks = append(portal.UI.PrivateLinks, privateLink)
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
							portal.UI.PrivateLinks = append(portal.UI.PrivateLinks, privateLink)
						}
					case "custom":
						args := strings.Join(h.RemainingArgs(), " ")
						args = strings.TrimSpace(args)
						switch {
						case strings.HasPrefix(args, "css path"):
							portal.UI.CustomCSSPath = strings.ReplaceAll(args, "css path ", "")
						case strings.HasPrefix(args, "css"):
							portal.UI.CustomCSSPath = strings.ReplaceAll(args, "css ", "")
						case strings.HasPrefix(args, "js path"):
							portal.UI.CustomJsPath = strings.ReplaceAll(args, "js path ", "")
						case strings.HasPrefix(args, "js"):
							portal.UI.CustomJsPath = strings.ReplaceAll(args, "js ", "")
						case strings.HasPrefix(args, "html header path"):
							args = strings.ReplaceAll(args, "html header path ", "")
							b, err := ioutil.ReadFile(args)
							if err != nil {
								return nil, h.Errf("%s %s subdirective: %s %v", rootDirective, subDirective, args, err)
							}
							for k, v := range ui.PageTemplates {
								headIndex := strings.Index(v, "<meta name=\"description\"")
								if headIndex < 1 {
									continue
								}
								v = v[:headIndex] + string(b) + v[headIndex:]
								ui.PageTemplates[k] = v
							}
						case args == "":
							return nil, h.Errf("%s %s directive has no value", rootDirective, subDirective)
						default:
							return nil, h.Errf("%s directive %q is unsupported", rootDirective, args)
						}
					case "static_asset":
						args := h.RemainingArgs()
						if len(args) != 3 {
							return nil, h.Errf("auth backend %s subdirective %s is malformed", rootDirective, subDirective)
						}
						prefix := "assets/"
						assetURI := args[0]
						assetContentType := args[1]
						assetPath := args[2]
						if !strings.HasPrefix(assetURI, prefix) {
							return nil, h.Errf("auth backend %s subdirective %s URI must be prefixed with %s, got %s",
								rootDirective, subDirective, prefix, assetURI)
						}
						if err := ui.StaticAssets.AddAsset(assetURI, assetContentType, assetPath); err != nil {
							return nil, h.Errf("auth backend %s subdirective %s failed: %s", rootDirective, subDirective, err)
						}
					default:
						return nil, h.Errf("unsupported subdirective for %s: %s", rootDirective, subDirective)
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
						portal.UserRegistrationConfig.Title = h.Val()
					case "disabled":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						if h.Val() == "yes" || h.Val() == "on" {
							portal.UserRegistrationConfig.Disabled = true
						}
					case "code":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						portal.UserRegistrationConfig.Code = h.Val()
					case "dropbox":
						if !h.NextArg() {
							return nil, h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
						}
						portal.UserRegistrationConfig.Dropbox = h.Val()
					case "require":
						args := strings.Join(h.RemainingArgs(), " ")
						args = strings.TrimSpace(args)
						switch args {
						case "accept terms":
							portal.UserRegistrationConfig.RequireAcceptTerms = true
						case "domain mx":
							portal.UserRegistrationConfig.RequireDomainMailRecord = true
						case "":
							return nil, h.Errf("%s directive has no value", rootDirective)
						default:
							return nil, h.Errf("%s directive %q is unsupported", rootDirective, args)
						}
					}
				}
			case "enable":
				args := strings.Join(h.RemainingArgs(), " ")
				switch args {
				case "source ip tracking":
					portal.TokenGrantorOptions.EnableSourceAddress = true
				default:
					return nil, h.Errf("unsupported directive for %s: %s", rootDirective, args)
				}
			case "validate":
				args := strings.Join(h.RemainingArgs(), " ")
				args = strings.TrimSpace(args)
				switch args {
				case "source address":
					portal.TokenValidatorOptions.ValidateSourceAddress = true
				case "":
					return nil, h.Errf("%s directive has no value", rootDirective)
				default:
					return nil, h.Errf("%s directive %q is unsupported", rootDirective, args)
				}
			default:
				return nil, h.Errf("unsupported root directive: %s", rootDirective)
			}
		}
	}

	if cryptoKeyConfigFound {
		configs, err := kms.ParseCryptoKeyConfigs(strings.Join(cryptoKeyConfig, "\n"))
		if err != nil {
			return nil, h.Errf("crypto key config error: %v", err)
		}
		portal.CryptoKeyConfigs = configs
	}

	if cryptoKeyStoreConfigFound {
		configs, err := kms.ParseCryptoKeyStoreConfig(strings.Join(cryptoKeyStoreConfig, "\n"))
		if err != nil {
			return nil, h.Errf("crypto key store config error: %v", err)
		}
		portal.CryptoKeyStoreConfig = configs
	}

	h.Reset()
	h.Next()

	return &portal, nil
}

func getRouteFromParseCaddyfileAuthenticator(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {

	portal, err := parseCaddyfileAuthenticator(h)
	if err != nil {
		return nil, err
	}

	pathMatcher := caddy.ModuleMap{
		"path": h.JSON(caddyhttp.MatchPath{"*"}),
	}

	route := caddyhttp.Route{
		HandlersRaw: []json.RawMessage{
			caddyconfig.JSONModuleObject(
				&AuthMiddleware{
					Portal: portal,
				},
				"handler",
				"authp",
				nil,
			),
		},
	}
	subroute := new(caddyhttp.Subroute)
	subroute.Routes = append([]caddyhttp.Route{route}, subroute.Routes...)
	return h.NewRoute(pathMatcher, subroute), nil

}

func backendValueErr(h httpcaddyfile.Helper, backendName, backendArg string) (*authn.Authenticator, error) {
	return nil, h.Errf("auth backend %s subdirective %s has no value", backendName, backendArg)
}

func backendUnsupportedValueErr(h httpcaddyfile.Helper, backendName, backendArg string) (*authn.Authenticator, error) {
	return nil, h.Errf("auth backend %s subdirective %s is unsupported", backendName, backendArg)
}

func backendPropErr(h httpcaddyfile.Helper, backendName, backendArg, attrName, attrErr string) (*authn.Authenticator, error) {
	return nil, h.Errf("auth backend %q subdirective %q key %q %s", backendName, backendArg, attrName, attrErr)
}

func backendValueConversionErr(h httpcaddyfile.Helper, backendName, k, v string, err error) (*authn.Authenticator, error) {
	return nil, h.Errf("auth backend %s subdirective %s value %q error: %v", backendName, k, v, err)
}
