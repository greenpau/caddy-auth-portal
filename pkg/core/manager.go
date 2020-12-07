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

package core

import (
	"crypto/rsa"
	"fmt"
	jwtacl "github.com/greenpau/caddy-auth-jwt/pkg/acl"
	jwtconfig "github.com/greenpau/caddy-auth-jwt/pkg/config"
	jwtvalidator "github.com/greenpau/caddy-auth-jwt/pkg/validator"
	"github.com/greenpau/caddy-auth-portal/pkg/cookies"
	"github.com/greenpau/caddy-auth-portal/pkg/registration"
	"github.com/greenpau/caddy-auth-portal/pkg/ui"
	"github.com/greenpau/go-identity"
	"go.uber.org/zap"
	"os"
	"path"
	"strings"
	"sync"
)

var defaultTheme string = "basic"

// AuthPortalManager provides access to all instances of the plugin.
type AuthPortalManager struct {
	mu               sync.Mutex
	Members          []*AuthPortal
	RefMembers       map[string]*AuthPortal
	PrimaryInstances map[string]*AuthPortal
	MemberCount      int
}

// Register registers authentication provider instance with the pool.
func (m *AuthPortalManager) Register(p *AuthPortal) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if p.Name == "" {
		m.MemberCount++
		p.Name = fmt.Sprintf("portal-%d", m.MemberCount)
	}
	if m.RefMembers == nil {
		m.RefMembers = make(map[string]*AuthPortal)
	}
	if _, exists := m.RefMembers[p.Name]; !exists {
		m.RefMembers[p.Name] = p
		m.Members = append(m.Members, p)
	}
	if p.Context == "" {
		p.Context = "default"
	}
	if m.PrimaryInstances == nil {
		m.PrimaryInstances = make(map[string]*AuthPortal)
	}
	if p.PrimaryInstance {
		if _, exists := m.PrimaryInstances[p.Context]; exists {
			// The time different check is necessary to determine whether this is a configuration
			// load or reload. Typically, the provisioning of a plugin would happen in a second.
			timeDiff := p.startedAt.Sub(m.PrimaryInstances[p.Context].startedAt).Milliseconds()
			if timeDiff < 1000 {
				return fmt.Errorf(
					"found more than one primary instance of the plugin for %s context: %v, %v",
					p.Context, m.PrimaryInstances, timeDiff,
				)
			}
		}
		m.PrimaryInstances[p.Context] = p
	}

	if !p.PrimaryInstance {
		return nil
	}

	if p.AuthURLPath == "" {
		return fmt.Errorf("%s: auth_url_path must be set", p.Name)
	}

	p.logger.Debug(
		"Authentication URL found",
		zap.String("instance_name", p.Name),
		zap.String("auth_url_path", p.AuthURLPath),
	)

	if p.TokenProvider.TokenName == "" {
		p.TokenProvider.TokenName = "access_token"
	}
	p.logger.Info(
		"JWT token name found",
		zap.String("instance_name", p.Name),
		zap.String("token_name", p.TokenProvider.TokenName),
	)

	var signingKeyFound bool
	var signingKeyID string
	var signingKey *rsa.PrivateKey

	if p.TokenProvider.TokenSecret != "" {
		signingKeyFound = true
		if p.TokenProvider.TokenSignMethod == "" {
			p.TokenProvider.TokenSignMethod = "HS512"
		}
	}

	if !signingKeyFound && os.Getenv("JWT_TOKEN_SECRET") != "" {
		signingKeyFound = true
		if p.TokenProvider.TokenSignMethod == "" {
			p.TokenProvider.TokenSignMethod = "HS512"
		}
		p.TokenProvider.TokenSecret = os.Getenv("JWT_TOKEN_SECRET")
	}

	if !signingKeyFound && p.TokenProvider.TokenRSAFiles != nil {
		if len(p.TokenProvider.TokenRSAFiles) > 0 {
			if err := jwtvalidator.LoadEncryptionKeys(p.TokenProvider); err != nil {
				return fmt.Errorf("%s: token provider error: %s", p.Name, err)
			}
			signingKeys := p.TokenProvider.GetKeys()
			if signingKeys == nil {
				return fmt.Errorf("%s: token provider has no keys", p.Name)
			}
			if len(signingKeys) != 1 {
				return fmt.Errorf("%s: token provider has more than one key", p.Name)
			}
			for k, v := range signingKeys {
				switch kt := v.(type) {
				case *rsa.PrivateKey:
					signingKeyID = k
					signingKey = v.(*rsa.PrivateKey)
				default:
					return fmt.Errorf("%s: token provider has unsupported key type %T for key ID %s", p.Name, kt, k)
				}
			}
			signingKeyFound = true
			if p.TokenProvider.TokenSignMethod == "" {
				p.TokenProvider.TokenSignMethod = "RS512"
			}
		}
	}

	if !signingKeyFound {
		return fmt.Errorf("%s: token_secret must be defined either "+
			"via JWT_TOKEN_SECRET environment variable or "+
			"via token_secret, token_rsa_file directive",
			p.Name,
		)
	}

	p.TokenProvider.TokenSignMethod = strings.ToUpper(p.TokenProvider.TokenSignMethod)

	if p.TokenProvider.TokenOrigin == "" {
		p.logger.Warn(
			"JWT token origin not found, using default",
			zap.String("instance_name", p.Name),
		)
		p.TokenProvider.TokenOrigin = "localhost"
	}

	p.logger.Debug(
		"JWT token origin found",
		zap.String("instance_name", p.Name),
		zap.String("token_origin", p.TokenProvider.TokenOrigin),
	)

	if p.TokenProvider.TokenLifetime == 0 {
		p.logger.Warn(
			"JWT token lifetime not found, using default",
			zap.String("instance_name", p.Name),
		)
		p.TokenProvider.TokenLifetime = 900
	}
	p.logger.Debug(
		"JWT token lifetime found",
		zap.String("instance_name", p.Name),
		zap.Int("token_lifetime", p.TokenProvider.TokenLifetime),
	)

	p.logger.Debug(
		"JWT token configuration provisioned",
		zap.String("instance_name", p.Name),
		zap.String("auth_url_path", p.AuthURLPath),
		zap.String("token_name", p.TokenProvider.TokenName),
		zap.String("token_origin", p.TokenProvider.TokenOrigin),
		zap.Int("token_lifetime", p.TokenProvider.TokenLifetime),
		zap.String("token_sign_method", p.TokenProvider.TokenSignMethod),
	)

	// Backend Validation
	if len(p.Backends) == 0 {
		return fmt.Errorf("%s: no valid backend found", p.Name)
	}

	backendNameRef := make(map[string]interface{})

	p.loginOptions = make(map[string]interface{})
	p.loginOptions["form_required"] = "no"
	p.loginOptions["realm_dropdown_required"] = "no"
	p.loginOptions["username_required"] = "no"
	p.loginOptions["password_required"] = "no"
	p.loginOptions["external_providers_required"] = "no"
	p.loginOptions["registration_required"] = "no"
	p.loginOptions["password_recovery_required"] = "no"
	var loginRealms []map[string]string
	var externalLoginProviders []map[string]string
	for _, backend := range p.Backends {
		backendName := backend.GetName()
		if backendName == "" {
			return fmt.Errorf("%s: backend name is required but missing", p.Name)
		}
		if _, exists := backendNameRef[backendName]; exists {
			return fmt.Errorf("%s: backend name %s is duplicate", p.Name, backendName)
		}
		backendNameRef[backendName] = true
		backendOptions := make(map[string]interface{})
		backendOptions["logger"] = p.logger
		backendOptions["token_provider"] = p.TokenProvider
		if err := backend.Configure(backendOptions); err != nil {
			return fmt.Errorf("%s: backend configuration error: %s", p.Name, err)
		}
		if err := backend.Validate(); err != nil {
			return fmt.Errorf("%s: backend validation error: %s", p.Name, err)
		}
		backendRealm := backend.GetRealm()
		backendMethod := backend.GetMethod()
		if backendMethod == "local" || backendMethod == "ldap" {
			loginRealm := make(map[string]string)
			loginRealm["realm"] = backendRealm
			loginRealm["default"] = "no"
			if backendMethod == "ldap" {
				loginRealm["label"] = strings.ToUpper(backendRealm)
			} else {
				loginRealm["label"] = strings.ToTitle(backendRealm)
				loginRealm["default"] = "yes"
			}
			loginRealms = append(loginRealms, loginRealm)
		}
		if backendMethod != "local" && backendMethod != "ldap" {
			externalLoginProvider := make(map[string]string)
			externalLoginProvider["endpoint"] = path.Join(p.AuthURLPath, backendMethod, backendRealm)
			externalLoginProvider["icon"] = backendMethod
			externalLoginProvider["realm"] = backendRealm
			switch backendRealm {
			case "google":
				externalLoginProvider["icon"] = "google"
				externalLoginProvider["text"] = "Google"
				externalLoginProvider["color"] = "red darken-1"
			case "facebook":
				externalLoginProvider["icon"] = "facebook"
				externalLoginProvider["text"] = "Facebook"
				externalLoginProvider["color"] = "blue darken-4"
			case "twitter":
				externalLoginProvider["icon"] = "twitter"
				externalLoginProvider["text"] = "Twitter"
				externalLoginProvider["color"] = "blue darken-1"
			case "linkedin":
				externalLoginProvider["icon"] = "linkedin"
				externalLoginProvider["text"] = "LinkedIn"
				externalLoginProvider["color"] = "blue darken-1"
			case "github":
				externalLoginProvider["icon"] = "github"
				externalLoginProvider["text"] = "Github"
				externalLoginProvider["color"] = "grey darken-3"
			case "windows":
				externalLoginProvider["icon"] = "windows"
				externalLoginProvider["text"] = "Microsoft"
				externalLoginProvider["color"] = "orange darken-1"
			case "azure":
				externalLoginProvider["icon"] = "windows"
				externalLoginProvider["text"] = "Azure"
				externalLoginProvider["color"] = "blue"
			case "aws", "amazon":
				externalLoginProvider["icon"] = "aws"
				externalLoginProvider["text"] = "AWS"
				externalLoginProvider["color"] = "blue-grey darken-2"
			default:
				externalLoginProvider["icon"] = "codepen"
				externalLoginProvider["text"] = backendRealm
				externalLoginProvider["color"] = "grey darken-3"
			}
			externalLoginProviders = append(externalLoginProviders, externalLoginProvider)
		}
		p.logger.Debug(
			"Provisioned authentication backend",
			zap.String("instance_name", p.Name),
			zap.String("backend_name", backendName),
			zap.String("backend_type", backendMethod),
			zap.String("backend_realm", backendRealm),
		)
	}

	if len(loginRealms) > 0 {
		p.loginOptions["form_required"] = "yes"
		p.loginOptions["username_required"] = "yes"
		p.loginOptions["password_required"] = "yes"
		p.loginOptions["realms"] = loginRealms
	}
	if len(loginRealms) > 1 {
		p.loginOptions["realm_dropdown_required"] = "yes"
	}
	if len(externalLoginProviders) > 0 {
		p.loginOptions["external_providers_required"] = "yes"
		p.loginOptions["external_providers"] = externalLoginProviders
	}

	// Cookies Validation
	if p.Cookies == nil {
		p.Cookies = &cookies.Cookies{}
	}

	// Setup User Registration
	if p.UserRegistration == nil {
		p.UserRegistration = &registration.Registration{}
	}
	if p.UserRegistration.Title == "" {
		p.UserRegistration.Title = "Sign Up"
	}
	if p.UserRegistration.Dropbox == "" {
		p.UserRegistration.Disabled = true
	}

	if !p.UserRegistration.Disabled {
		p.loginOptions["registration_required"] = "yes"
		if p.UserRegistrationDatabase == nil {
			p.UserRegistrationDatabase = identity.NewDatabase()
			fileInfo, err := os.Stat(p.UserRegistration.Dropbox)
			if err != nil {
				if os.IsNotExist(err) {
					if err := p.UserRegistrationDatabase.SaveToFile(p.UserRegistration.Dropbox); err != nil {
						return fmt.Errorf("%s: registration dropbox setup failed: %s", p.Name, err)
					}
				} else {
					return fmt.Errorf("%s: registration dropbox metadata read failed: %s", p.Name, err)
				}
			} else {
				if fileInfo.IsDir() {
					return fmt.Errorf("%s: registration dropbox is a directory", p.Name)
				}
			}
			if err := p.UserRegistrationDatabase.LoadFromFile(p.UserRegistration.Dropbox); err != nil {
				return fmt.Errorf("%s: registration dropbox load failed: %s", p.Name, err)
			}
		}
	}

	p.logger.Debug(
		"Provisioned registration endpoint",
		zap.String("instance_name", p.Name),
		zap.String("dropbox", p.UserRegistration.Dropbox),
	)

	// Setup User Interface
	if p.UserInterface == nil {
		p.UserInterface = &ui.UserInterfaceParameters{}
	}

	if p.UserInterface.Templates == nil {
		p.UserInterface.Templates = make(map[string]string)
	}

	p.uiFactory = ui.NewUserInterfaceFactory()
	if p.UserInterface.Title == "" {
		p.uiFactory.Title = "Sign In"
	} else {
		p.uiFactory.Title = p.UserInterface.Title
	}

	if p.UserInterface.CustomCSSPath != "" {
		p.uiFactory.CustomCSSPath = p.UserInterface.CustomCSSPath
		if err := ui.StaticAssets.AddAsset("assets/css/custom.css", "text/css", p.UserInterface.CustomCSSPath); err != nil {
			return fmt.Errorf("%s: custom css: %s", p.Name, err)
		}
	}

	if p.UserInterface.CustomJsPath != "" {
		p.uiFactory.CustomJsPath = p.UserInterface.CustomJsPath
		if err := ui.StaticAssets.AddAsset("assets/js/custom.js", "application/javascript", p.UserInterface.CustomJsPath); err != nil {
			return fmt.Errorf("%s: custom js: %s", p.Name, err)
		}
	}

	if p.UserInterface.LogoURL != "" {
		p.uiFactory.LogoURL = p.UserInterface.LogoURL
		p.uiFactory.LogoDescription = p.UserInterface.LogoDescription
	} else {
		p.uiFactory.LogoURL = path.Join(p.AuthURLPath, p.uiFactory.LogoURL)
	}

	p.uiFactory.ActionEndpoint = p.AuthURLPath

	if len(p.UserInterface.PrivateLinks) > 0 {
		p.uiFactory.PrivateLinks = p.UserInterface.PrivateLinks
	}

	if len(p.UserInterface.Realms) > 0 {
		p.uiFactory.Realms = p.UserInterface.Realms
	}

	if p.UserInterface.Theme == "" {
		p.UserInterface.Theme = defaultTheme
	}
	if _, exists := ui.Themes[p.UserInterface.Theme]; !exists {
		return fmt.Errorf(
			"%s: UI settings validation error, theme %s does not exist",
			p.Name, p.UserInterface.Theme,
		)
	}

	if p.UserInterface.PasswordRecoveryEnabled {
		p.loginOptions["password_recovery_required"] = "yes"
	}

	p.logger.Debug(
		"Provisioned authentication user interface parameters",
		zap.String("instance_name", p.Name),
		zap.String("title", p.uiFactory.Title),
		zap.String("logo_url", p.uiFactory.LogoURL),
		zap.String("logo_description", p.uiFactory.LogoDescription),
		zap.Any("action_endpoint", p.uiFactory.ActionEndpoint),
		zap.Any("private_links", p.uiFactory.PrivateLinks),
		zap.Any("realms", p.uiFactory.Realms),
		zap.String("theme", p.UserInterface.Theme),
	)

	// User Interface Templates
	for k := range ui.PageTemplates {
		tmplNameParts := strings.SplitN(k, "/", 2)
		tmplTheme := tmplNameParts[0]
		tmplName := tmplNameParts[1]
		if tmplTheme != p.UserInterface.Theme {
			continue
		}
		if _, exists := p.UserInterface.Templates[tmplName]; !exists {
			p.logger.Debug(
				"Provisioning default authentication user interface templates",
				zap.String("instance_name", p.Name),
				zap.String("template_theme", tmplTheme),
				zap.String("template_name", tmplName),
			)
			if err := p.uiFactory.AddBuiltinTemplate(k); err != nil {
				return fmt.Errorf(
					"%s: UI settings validation error, failed loading built-in %s template from %s theme: %s",
					p.Name, tmplName, tmplTheme, err,
				)
			}
			p.uiFactory.Templates[tmplName] = p.uiFactory.Templates[k]
		}
	}

	for tmplName, tmplPath := range p.UserInterface.Templates {
		p.logger.Debug(
			"Provisioning non-default authentication user interface templates",
			zap.String("instance_name", p.Name),
			zap.String("template_name", tmplName),
			zap.String("template_path", tmplPath),
		)
		if err := p.uiFactory.AddTemplate(tmplName, tmplPath); err != nil {
			return fmt.Errorf(
				"%s: UI settings validation error, failed loading %s template from %s: %s",
				p.Name, tmplName, tmplPath, err,
			)
		}
	}

	p.TokenValidator = jwtvalidator.NewTokenValidator()
	tokenConfig := jwtconfig.NewCommonTokenConfig()
	tokenConfig.TokenName = p.TokenProvider.TokenName

	switch p.TokenProvider.TokenSignMethod {
	case "HS512", "HS384", "HS256":
		tokenConfig.TokenSecret = p.TokenProvider.TokenSecret
	default:
		if err := tokenConfig.AddRSAPublicKey(signingKeyID, signingKey); err != nil {
			return fmt.Errorf("%s: token provider failed to add key ID %s: %s", p.Name, signingKeyID, err)
		}
		if err := jwtvalidator.LoadEncryptionKeys(tokenConfig); err != nil {
			return fmt.Errorf("%s: token provider error: %s", p.Name, err)
		}
		verifyKeys := tokenConfig.GetKeys()
		if verifyKeys == nil {
			return fmt.Errorf("%s: token provider has no keys", p.Name)
		}
		for k, v := range verifyKeys {
			switch kt := v.(type) {
			case *rsa.PublicKey:
			default:
				return fmt.Errorf("%s: token provider has unsupported key type %T for key ID %s", p.Name, kt, k)
			}
		}
	}
	p.TokenValidator.TokenConfigs = []*jwtconfig.CommonTokenConfig{tokenConfig}
	if err := p.TokenValidator.ConfigureTokenBackends(); err != nil {
		return fmt.Errorf(
			"%s: token validator backend configuration failed: %s",
			p.Name, err,
		)
	}
	entry := jwtacl.NewAccessListEntry()
	entry.Allow()
	if err := entry.SetClaim("roles"); err != nil {
		return fmt.Errorf(
			"%s: default access list configuration error: %s",
			p.Name, err,
		)
	}
	for _, v := range []string{"anonymous", "guest", "*"} {
		if err := entry.AddValue(v); err != nil {
			return fmt.Errorf(
				"%s: default access list configuration error: %s",
				p.Name, err,
			)
		}
	}
	p.TokenValidator.AccessList = append(p.TokenValidator.AccessList, entry)
	p.logger.Info(
		"JWT token validator provisioned",
		zap.String("instance_name", p.Name),
		zap.Any("access_list", p.TokenValidator.AccessList),
	)

	p.TokenValidator.TokenSources = []string{"cookie", "header", "query"}

	p.TokenValidator.SetTokenName(p.TokenProvider.TokenName)
	p.Provisioned = true
	return nil
}

// Provision provisions non-primary instances in an authentication context.
func (m *AuthPortalManager) Provision(name string) error {
	if name == "" {
		return fmt.Errorf("authentication provider name is empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.RefMembers == nil {
		return fmt.Errorf("no member reference found")
	}
	p, exists := m.RefMembers[name]
	if !exists {
		return fmt.Errorf("authentication provider %s not found", name)
	}
	if p == nil {
		return fmt.Errorf("authentication provider %s is nil", name)
	}
	if p.Provisioned {
		return nil
	}
	if p.Context == "" {
		p.Context = "default"
	}
	primaryInstance, primaryInstanceExists := m.PrimaryInstances[p.Context]
	if !primaryInstanceExists {
		p.ProvisionFailed = true
		return fmt.Errorf("no primary authentication provider found in %s context when configuring %s", p.Context, name)
	}

	if p.AuthURLPath == "" {
		p.AuthURLPath = primaryInstance.AuthURLPath
	}

	if p.TokenProvider == nil {
		p.TokenProvider = jwtconfig.NewCommonTokenConfig()
	}

	if p.TokenProvider.TokenName == "" {
		p.TokenProvider.TokenName = primaryInstance.TokenProvider.TokenName
	}

	if p.TokenProvider.TokenSecret == "" {
		p.TokenProvider.TokenSecret = primaryInstance.TokenProvider.TokenSecret
	}

	if p.TokenProvider.TokenOrigin == "" {
		p.TokenProvider.TokenOrigin = primaryInstance.TokenProvider.TokenOrigin
	}

	if p.TokenProvider.TokenLifetime == 0 {
		p.TokenProvider.TokenLifetime = primaryInstance.TokenProvider.TokenLifetime
	}

	if p.TokenProvider.TokenRSAFiles == nil {
		p.TokenProvider.TokenRSAFiles = primaryInstance.TokenProvider.TokenRSAFiles
	}

	var signingKeyFound bool
	var signingKeyID string
	var signingKey *rsa.PrivateKey

	if p.TokenProvider.TokenSecret != "" {
		signingKeyFound = true
		if p.TokenProvider.TokenSignMethod == "" {
			p.TokenProvider.TokenSignMethod = "HS512"
		}
	}

	if !signingKeyFound && os.Getenv("JWT_TOKEN_SECRET") != "" {
		signingKeyFound = true
		if p.TokenProvider.TokenSignMethod == "" {
			p.TokenProvider.TokenSignMethod = "HS512"
		}
		p.TokenProvider.TokenSecret = os.Getenv("JWT_TOKEN_SECRET")
	}

	if !signingKeyFound && p.TokenProvider.TokenRSAFiles != nil {
		if len(p.TokenProvider.TokenRSAFiles) > 0 {
			if err := jwtvalidator.LoadEncryptionKeys(p.TokenProvider); err != nil {
				return fmt.Errorf("%s: token provider error: %s", p.Name, err)
			}
			signingKeys := p.TokenProvider.GetKeys()
			if signingKeys == nil {
				return fmt.Errorf("%s: token provider has no keys", p.Name)
			}
			if len(signingKeys) != 1 {
				return fmt.Errorf("%s: token provider has more than one key", p.Name)
			}
			for k, v := range signingKeys {
				switch kt := v.(type) {
				case *rsa.PrivateKey:
					signingKeyID = k
					signingKey = v.(*rsa.PrivateKey)
				default:
					return fmt.Errorf("%s: token provider has unsupported key type %T for key ID %s", p.Name, kt, k)
				}
			}
			signingKeyFound = true
			if p.TokenProvider.TokenSignMethod == "" {
				p.TokenProvider.TokenSignMethod = "RS512"
			}
		}
	}

	if !signingKeyFound {
		return fmt.Errorf("%s: token_secret must be defined either "+
			"via JWT_TOKEN_SECRET environment variable or "+
			"via token_secret, token_rsa_file directive",
			p.Name,
		)
	}

	p.TokenProvider.TokenSignMethod = strings.ToUpper(p.TokenProvider.TokenSignMethod)

	p.logger.Debug(
		"JWT token configuration provisioned",
		zap.String("instance_name", p.Name),
		zap.String("auth_url_path", p.AuthURLPath),
		zap.String("token_name", p.TokenProvider.TokenName),
		zap.String("token_origin", p.TokenProvider.TokenOrigin),
		zap.Int("token_lifetime", p.TokenProvider.TokenLifetime),
		zap.String("token_sign_method", p.TokenProvider.TokenSignMethod),
	)

	// Backend Validation
	if len(p.Backends) == 0 {
		p.Backends = primaryInstance.Backends
	} else {
		backendNameRef := make(map[string]interface{})
		for _, backend := range p.Backends {
			backendName := backend.GetName()
			if backendName == "" {
				return fmt.Errorf("%s: backend name is required but missing", p.Name)
			}
			if _, exists := backendNameRef[backendName]; exists {
				return fmt.Errorf("%s: backend name %s is duplicate", p.Name, backendName)
			}
			backendNameRef[backendName] = true

			backendOptions := make(map[string]interface{})
			backendOptions["logger"] = p.logger
			backendOptions["token_provider"] = p.TokenProvider
			if err := backend.Configure(backendOptions); err != nil {
				return fmt.Errorf("%s: backend configuration error: %s", p.Name, err)
			}
			if err := backend.Validate(); err != nil {
				return fmt.Errorf("%s: backend validation error: %s", p.Name, err)
			}
			p.logger.Debug(
				"Provisioned authentication backend",
				zap.String("instance_name", p.Name),
				zap.String("backend_name", backendName),
				zap.String("backend_type", backend.GetMethod()),
			)
		}
	}

	// Cookies Validation
	if p.Cookies == nil {
		p.Cookies = &cookies.Cookies{}
	}

	// Setup User Registration
	p.UserRegistration = primaryInstance.UserRegistration
	p.UserRegistrationDatabase = primaryInstance.UserRegistrationDatabase

	// User Interface Settings
	if p.UserInterface == nil {
		p.UserInterface = &ui.UserInterfaceParameters{}
	}

	if p.UserInterface.Templates == nil {
		p.UserInterface.Templates = primaryInstance.UserInterface.Templates
	}

	if p.UserInterface.Templates == nil {
		p.UserInterface.Templates = make(map[string]string)
	}

	p.uiFactory = ui.NewUserInterfaceFactory()
	if p.UserInterface.Title == "" {
		p.uiFactory.Title = primaryInstance.uiFactory.Title
	} else {
		p.uiFactory.Title = p.UserInterface.Title
	}

	if p.UserInterface.CustomCSSPath == "" {
		p.uiFactory.CustomCSSPath = primaryInstance.uiFactory.CustomCSSPath
	}

	if p.UserInterface.CustomJsPath == "" {
		p.uiFactory.CustomJsPath = primaryInstance.uiFactory.CustomJsPath
	}

	if p.UserInterface.LogoURL == "" {
		p.uiFactory.LogoURL = primaryInstance.uiFactory.LogoURL
		p.uiFactory.LogoDescription = primaryInstance.uiFactory.LogoDescription
	} else {
		p.uiFactory.LogoURL = p.UserInterface.LogoURL
		p.uiFactory.LogoDescription = p.UserInterface.LogoDescription
	}

	p.uiFactory.ActionEndpoint = p.AuthURLPath

	if len(p.UserInterface.PrivateLinks) == 0 {
		p.UserInterface.PrivateLinks = primaryInstance.UserInterface.PrivateLinks
	}

	if len(p.UserInterface.PrivateLinks) > 0 {
		p.uiFactory.PrivateLinks = p.UserInterface.PrivateLinks
	}

	if len(p.UserInterface.Realms) == 0 {
		p.uiFactory.Realms = primaryInstance.UserInterface.Realms
	}

	if len(p.UserInterface.Realms) > 0 {
		p.uiFactory.Realms = p.UserInterface.Realms
	}

	p.logger.Debug(
		"Provisioned authentication user interface parameters for non-primaryInstance instance",
		zap.String("instance_name", p.Name),
		zap.String("title", p.uiFactory.Title),
		zap.String("logo_url", p.uiFactory.LogoURL),
		zap.String("logo_description", p.uiFactory.LogoDescription),
		zap.Any("action_endpoint", p.uiFactory.ActionEndpoint),
		zap.Any("private_links", p.uiFactory.PrivateLinks),
		zap.Any("realms", p.uiFactory.Realms),
	)

	// User Interface Templates
	if p.UserInterface.Theme == "" {
		p.UserInterface.Theme = primaryInstance.UserInterface.Theme
	}
	if _, exists := ui.Themes[p.UserInterface.Theme]; !exists {
		return fmt.Errorf(
			"%s: UI settings validation error, theme %s does not exist",
			p.Name, p.UserInterface.Theme,
		)
	}

	for k := range ui.PageTemplates {
		tmplNameParts := strings.SplitN(k, "/", 2)
		tmplTheme := tmplNameParts[0]
		tmplName := tmplNameParts[1]
		if tmplTheme != p.UserInterface.Theme {
			continue
		}
		if _, exists := p.UserInterface.Templates[tmplName]; !exists {
			p.logger.Debug(
				"Provisioning default authentication user interface templates",
				zap.String("instance_name", p.Name),
				zap.String("template_theme", tmplTheme),
				zap.String("template_name", tmplName),
			)
			if err := p.uiFactory.AddBuiltinTemplate(k); err != nil {
				return fmt.Errorf(
					"%s: UI settings validation error, failed loading built-in %s template from %s theme: %s",
					p.Name, tmplName, tmplTheme, err,
				)
			}
			p.uiFactory.Templates[tmplName] = p.uiFactory.Templates[k]
		}
	}

	for tmplName, tmplPath := range p.UserInterface.Templates {
		p.logger.Debug(
			"Provisioning non-default authentication user interface templates",
			zap.String("instance_name", p.Name),
			zap.String("template_name", tmplName),
			zap.String("template_path", tmplPath),
		)
		if err := p.uiFactory.AddTemplate(tmplName, tmplPath); err != nil {
			return fmt.Errorf(
				"%s: UI settings validation error, failed loading %s template from %s: %s",
				p.Name, tmplName, tmplPath, err,
			)
		}
	}

	// JWT Token Validator
	p.TokenValidator = jwtvalidator.NewTokenValidator()
	tokenConfig := jwtconfig.NewCommonTokenConfig()
	tokenConfig.TokenName = p.TokenProvider.TokenName

	switch p.TokenProvider.TokenSignMethod {
	case "HS512", "HS384", "HS256":
		tokenConfig.TokenSecret = p.TokenProvider.TokenSecret
	default:
		if err := tokenConfig.AddRSAPublicKey(signingKeyID, signingKey); err != nil {
			return fmt.Errorf("%s: token provider failed to add key ID %s: %s", p.Name, signingKeyID, err)
		}
		if err := jwtvalidator.LoadEncryptionKeys(tokenConfig); err != nil {
			return fmt.Errorf("%s: token provider error: %s", p.Name, err)
		}
		verifyKeys := tokenConfig.GetKeys()
		if verifyKeys == nil {
			return fmt.Errorf("%s: token provider has no keys", p.Name)
		}
		for k, v := range verifyKeys {
			switch kt := v.(type) {
			case *rsa.PublicKey:
			default:
				return fmt.Errorf("%s: token provider has unsupported key type %T for key ID %s", p.Name, kt, k)
			}
		}
	}

	p.TokenValidator.TokenConfigs = []*jwtconfig.CommonTokenConfig{tokenConfig}
	if err := p.TokenValidator.ConfigureTokenBackends(); err != nil {
		return fmt.Errorf(
			"%s: token validator backend configuration failed: %s",
			p.Name, err,
		)
	}

	// JWT Access List
	entry := jwtacl.NewAccessListEntry()
	entry.Allow()
	if err := entry.SetClaim("roles"); err != nil {
		return fmt.Errorf(
			"%s: default access list configuration error: %s",
			p.Name, err,
		)
	}
	for _, v := range []string{"anonymous", "guest", "*"} {
		if err := entry.AddValue(v); err != nil {
			return fmt.Errorf(
				"%s: default access list configuration error: %s",
				p.Name, err,
			)
		}
	}
	p.TokenValidator.AccessList = append(p.TokenValidator.AccessList, entry)

	p.logger.Info(
		"JWT token validator provisioned successfully",
		zap.String("instance_name", p.Name),
		zap.Any("access_list", p.TokenValidator.AccessList),
	)

	p.TokenValidator.TokenSources = []string{"cookie", "header", "query"}

	p.TokenValidator.SetTokenName(p.TokenProvider.TokenName)

	// Wrap up
	p.Provisioned = true
	p.ProvisionFailed = false

	return nil
}
