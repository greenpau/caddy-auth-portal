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
	"github.com/greenpau/caddy-auth-portal/pkg/backends"
	"github.com/greenpau/caddy-auth-portal/pkg/cache"
	"github.com/greenpau/caddy-auth-portal/pkg/cookie"
	"github.com/greenpau/caddy-auth-portal/pkg/errors"
	"github.com/greenpau/caddy-auth-portal/pkg/registration"
	"github.com/greenpau/caddy-auth-portal/pkg/transformer"
	"github.com/greenpau/caddy-auth-portal/pkg/ui"
	"github.com/greenpau/caddy-authorize/pkg/acl"
	"github.com/greenpau/caddy-authorize/pkg/kms"
	"github.com/greenpau/caddy-authorize/pkg/options"
	"github.com/greenpau/caddy-authorize/pkg/validator"
	"github.com/greenpau/go-identity"
	"go.uber.org/zap"
	"path"
	"strings"
)

func (mgr *InstanceManager) configure(p, m *Authenticator) error {
	if err := mgr.configureEssentials(p, m); err != nil {
		return err
	}
	if err := mgr.configureCryptoKeyStore(p, m); err != nil {
		return err
	}
	if err := mgr.configureBackends(p, m); err != nil {
		return err
	}
	if err := mgr.configureUserRegistration(p, m); err != nil {
		return err
	}
	if err := mgr.configureUserInterface(p, m); err != nil {
		return err
	}
	if err := mgr.configureUserTransformer(p, m); err != nil {
		return err
	}
	return nil
}

func (mgr *InstanceManager) configureEssentials(primaryInstance, m *Authenticator) error {
	// Configure session cache.
	if m.PrimaryInstance {
		m.sessions = cache.NewSessionCache()
		m.sessions.Run()
	} else {
		m.sessions = primaryInstance.sessions
	}

	// Configure sandbox cache.
	if m.PrimaryInstance {
		m.sandboxes = cache.NewSandboxCache()
		m.sandboxes.Run()
	} else {
		m.sandboxes = primaryInstance.sandboxes
	}

	// Cookies Validation
	if m.CookieConfig == nil {
		if m.PrimaryInstance {
			c, err := cookie.NewFactory(m.CookieConfig)
			if err != nil {
				return err
			}
			m.cookie = c
		} else {
			m.cookie = primaryInstance.cookie
		}
	} else {
		c, err := cookie.NewFactory(m.CookieConfig)
		if err != nil {
			return err
		}
		m.cookie = c
	}

	return nil
}

func (mgr *InstanceManager) configureBackends(primaryInstance, m *Authenticator) error {
	m.logger.Debug(
		"Configuring authentication backends",
		zap.String("instance_name", m.Name),
		zap.Int("backend_count", len(m.BackendConfigs)),
	)
	// Configure authentication backends.
	if len(m.BackendConfigs) == 0 {
		if m.PrimaryInstance {
			return errors.ErrNoBackendsFound.WithArgs(m.Context, m.Name)
		}
		m.backends = primaryInstance.backends
	}

	backendNameRef := make(map[string]interface{})
	var loginRealms []map[string]string
	var externalLoginProviders []map[string]string

	m.loginOptions = make(map[string]interface{})
	m.loginOptions["form_required"] = "no"
	m.loginOptions["realm_dropdown_required"] = "no"
	m.loginOptions["identity_required"] = "no"
	m.loginOptions["external_providers_required"] = "no"
	m.loginOptions["registration_required"] = "no"
	m.loginOptions["password_recovery_required"] = "no"

	for _, cfg := range m.BackendConfigs {
		backend, err := backends.NewBackend(&cfg, m.logger)
		if err != nil {
			return errors.ErrBackendConfigurationFailed.WithArgs(m.Context, m.Name, err)
		}
		if err := backend.Configure(); err != nil {
			return errors.ErrBackendConfigurationFailed.WithArgs(m.Context, m.Name, err)
		}
		if err := backend.Validate(); err != nil {
			return errors.ErrBackendValidationFailed.WithArgs(m.Context, m.Name, err)
		}
		backendName := backend.GetName()

		if _, exists := backendNameRef[backendName]; exists {
			return errors.ErrDuplicateBackendName.WithArgs(backendName, m.Context, m.Name)
		}
		backendNameRef[backendName] = true
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
			externalLoginProvider["endpoint"] = path.Join(backendMethod, backendRealm)
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
		m.backends = append(m.backends, backend)
		m.logger.Debug(
			"Provisioned authentication backend",
			zap.String("instance_name", m.Name),
			zap.String("backend_name", backendName),
			zap.String("backend_type", backendMethod),
			zap.String("backend_realm", backendRealm),
		)
	}

	if len(loginRealms) > 0 {
		m.loginOptions["form_required"] = "yes"
		m.loginOptions["identity_required"] = "yes"
		m.loginOptions["realms"] = loginRealms
	}
	if len(loginRealms) > 1 {
		m.loginOptions["realm_dropdown_required"] = "yes"
	}
	if len(externalLoginProviders) > 0 {
		m.loginOptions["external_providers_required"] = "yes"
		m.loginOptions["external_providers"] = externalLoginProviders
	}

	m.logger.Debug(
		"Provisioned login options",
		zap.Any("options", m.loginOptions),
	)
	return nil
}

func (mgr *InstanceManager) configureUserRegistration(primaryInstance, m *Authenticator) error {
	// Setup User Registration
	if m.UserRegistrationConfig == nil {
		if m.PrimaryInstance {
			m.UserRegistrationConfig = &registration.Config{}
		} else {
			m.UserRegistrationConfig = primaryInstance.UserRegistrationConfig
			m.registrar = primaryInstance.registrar
		}
	}
	if m.UserRegistrationConfig.Dropbox == "" {
		m.UserRegistrationConfig.Disabled = true
	}
	if m.UserRegistrationConfig.Disabled {
		return nil
	}
	if m.UserRegistrationConfig.Title == "" {
		m.UserRegistrationConfig.Title = "Sign Up"
	}
	m.loginOptions["registration_required"] = "yes"
	if m.registrar == nil {
		db, err := identity.NewDatabase(m.UserRegistrationConfig.Dropbox)
		if err != nil {
			return errors.ErrUserRegistrationConfig.WithArgs(m.Name, err)
		}
		m.registrar = db
	}
	m.logger.Debug(
		"Provisioned registration endpoint",
		zap.String("instance_name", m.Name),
		zap.String("dropbox", m.UserRegistrationConfig.Dropbox),
	)
	return nil
}

func (mgr *InstanceManager) configureUserInterface(primaryInstance, m *Authenticator) error {
	// Setup User Interface
	if m.UI == nil {
		m.UI = &ui.Parameters{}
	}

	if m.UI.Templates == nil {
		m.UI.Templates = make(map[string]string)
	}

	m.ui = ui.NewFactory()
	if m.UI.Title == "" {
		m.ui.Title = "Sign In"
	} else {
		m.ui.Title = m.UI.Title
	}

	if m.UI.CustomCSSPath != "" {
		m.ui.CustomCSSPath = m.UI.CustomCSSPath
		if err := ui.StaticAssets.AddAsset("assets/css/custom.css", "text/css", m.UI.CustomCSSPath); err != nil {
			return errors.ErrStaticAssetAddFailed.WithArgs("assets/css/custom.css", "text/css", m.UI.CustomCSSPath, m.Context, m.Name, err)
		}
	}

	if m.UI.CustomJsPath != "" {
		m.ui.CustomJsPath = m.UI.CustomJsPath
		if err := ui.StaticAssets.AddAsset("assets/js/custom.js", "application/javascript", m.UI.CustomJsPath); err != nil {
			return errors.ErrStaticAssetAddFailed.WithArgs("assets/js/custom.js", "application/javascript", m.UI.CustomJsPath, m.Context, m.Name, err)
		}
	}

	if m.UI.LogoURL != "" {
		m.ui.LogoURL = m.UI.LogoURL
		m.ui.LogoDescription = m.UI.LogoDescription
	} else {
		m.ui.LogoURL = path.Join(m.ui.LogoURL)
	}

	// TODO: how does ui factory function.
	//m.ui.ActionEndpoint = m.AuthURLPath

	if len(m.UI.PrivateLinks) > 0 {
		m.ui.PrivateLinks = m.UI.PrivateLinks
	}

	if len(m.UI.Realms) > 0 {
		m.ui.Realms = m.UI.Realms
	}

	if m.UI.Theme == "" {
		m.UI.Theme = "basic"
	}
	if _, exists := ui.Themes[m.UI.Theme]; !exists {
		return errors.ErrUserInterfaceThemeNotFound.WithArgs(m.Context, m.Name, m.UI.Theme)
	}

	if m.UI.PasswordRecoveryEnabled {
		m.loginOptions["password_recovery_required"] = "yes"
	}

	m.logger.Debug(
		"Provisioned authentication user interface parameters",
		zap.String("instance_name", m.Name),
		zap.String("title", m.ui.Title),
		zap.String("logo_url", m.ui.LogoURL),
		zap.String("logo_description", m.ui.LogoDescription),
		zap.Any("action_endpoint", m.ui.ActionEndpoint),
		zap.Any("private_links", m.ui.PrivateLinks),
		zap.Any("realms", m.ui.Realms),
		zap.String("theme", m.UI.Theme),
	)

	// User Interface Templates
	for k := range ui.PageTemplates {
		tmplNameParts := strings.SplitN(k, "/", 2)
		tmplTheme := tmplNameParts[0]
		tmplName := tmplNameParts[1]
		if tmplTheme != m.UI.Theme {
			continue
		}
		if _, exists := m.UI.Templates[tmplName]; !exists {
			m.logger.Debug(
				"Provisioning default authentication user interface templates",
				zap.String("instance_name", m.Name),
				zap.String("template_theme", tmplTheme),
				zap.String("template_name", tmplName),
			)
			if err := m.ui.AddBuiltinTemplate(k); err != nil {
				return errors.ErrUserInterfaceBuiltinTemplateAddFailed.WithArgs(m.Context, m.Name, tmplName, tmplTheme, err)
			}
			m.ui.Templates[tmplName] = m.ui.Templates[k]
		}
	}

	for tmplName, tmplPath := range m.UI.Templates {
		m.logger.Debug(
			"Provisioning non-default authentication user interface templates",
			zap.String("instance_name", m.Name),
			zap.String("template_name", tmplName),
			zap.String("template_path", tmplPath),
		)
		if err := m.ui.AddTemplate(tmplName, tmplPath); err != nil {
			return errors.ErrUserInterfaceCustomTemplateAddFailed.WithArgs(m.Context, m.Name, tmplName, tmplPath, err)
		}
	}
	return nil
}

func (mgr *InstanceManager) configureUserTransformer(primaryInstance, m *Authenticator) error {
	if len(m.UserTransformerConfigs) == 0 {
		if !m.PrimaryInstance {
			m.transformer = primaryInstance.transformer
		}
		return nil
	}
	if m.PrimaryInstance {
		tr, err := transformer.NewFactory(m.UserTransformerConfigs)
		if err != nil {
			return err
		}
		m.transformer = tr
	} else {
		m.transformer = primaryInstance.transformer
	}
	m.logger.Debug(
		"Provisioned user transforms",
		zap.String("instance_name", m.Name),
		zap.Any("transforms", m.UserTransformerConfigs),
	)
	return nil
}

func (mgr *InstanceManager) configureCryptoKeyStore(primaryInstance, m *Authenticator) error {
	if len(m.AccessListConfigs) == 0 {
		if m.PrimaryInstance {
			m.AccessListConfigs = []*acl.RuleConfiguration{
				{
					// Admin users can access everything.
					Conditions: []string{"match roles authp/admin authp/user authp/guest superuser superadmin"},
					Action:     `allow stop`,
				},
			}
		} else {
			m.AccessListConfigs = primaryInstance.AccessListConfigs
		}
	}

	m.logger.Debug(
		"Provided authentication acl configuration",
		zap.String("instance_name", m.Name),
		zap.Any("acl", m.AccessListConfigs),
	)

	if m.TokenValidatorOptions == nil {
		if m.PrimaryInstance {
			m.TokenValidatorOptions = options.NewTokenValidatorOptions()
		} else {
			m.TokenValidatorOptions = primaryInstance.TokenValidatorOptions
		}
	}
	m.TokenValidatorOptions.ValidateBearerHeader = true
	// The below line is disabled because path match is not part of the ACL.
	// m.TokenValidatorOptions.ValidateMethodPath = true

	accessList := acl.NewAccessList()
	accessList.SetLogger(m.logger)
	ctx := context.Background()
	if err := accessList.AddRules(ctx, m.AccessListConfigs); err != nil {
		return errors.ErrCryptoKeyStoreConfig.WithArgs(m.Name, err)
	}

	m.keystore = kms.NewCryptoKeyStore()
	m.keystore.SetLogger(m.logger)

	// Load token configuration into key managers, extract token verification
	// keys and add them to token validator.
	if m.CryptoKeyStoreConfig == nil && !m.PrimaryInstance {
		m.CryptoKeyStoreConfig = primaryInstance.CryptoKeyStoreConfig
	}
	if len(m.CryptoKeyConfigs) == 0 && !m.PrimaryInstance {
		m.CryptoKeyConfigs = primaryInstance.CryptoKeyConfigs
	}

	if m.CryptoKeyStoreConfig != nil {
		// Add default token name, lifetime, etc.
		if err := m.keystore.AddDefaults(m.CryptoKeyStoreConfig); err != nil {
			return errors.ErrCryptoKeyStoreConfig.WithArgs(m.Name, err)
		}
	}

	if len(m.CryptoKeyConfigs) == 0 {
		if m.PrimaryInstance {
			if err := m.keystore.AutoGenerate("default", "ES512"); err != nil {
				return errors.ErrCryptoKeyStoreConfig.WithArgs(m.Name, err)
			}
		} else {
			m.CryptoKeyConfigs = primaryInstance.CryptoKeyConfigs
			m.keystore = primaryInstance.keystore
		}
	} else {
		if err := m.keystore.AddKeysWithConfigs(m.CryptoKeyConfigs); err != nil {
			return errors.ErrCryptoKeyStoreConfig.WithArgs(m.Name, err)
		}
	}

	if err := m.keystore.HasVerifyKeys(); err != nil {
		return errors.ErrCryptoKeyStoreConfig.WithArgs(m.Name, err)
	}

	m.validator = validator.NewTokenValidator()
	if err := m.validator.Configure(ctx, m.keystore.GetVerifyKeys(), accessList, m.TokenValidatorOptions); err != nil {
		return errors.ErrCryptoKeyStoreConfig.WithArgs(m.Name, err)
	}

	m.logger.Debug(
		"Provisioned validator acl",
		zap.String("instance_name", m.Name),
	)
	return nil
}
