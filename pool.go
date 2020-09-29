package portal

import (
	"fmt"
	"github.com/greenpau/caddy-auth-jwt"
	"github.com/greenpau/caddy-auth-portal/pkg/cookies"
	"github.com/greenpau/caddy-auth-portal/pkg/registration"
	"github.com/greenpau/caddy-auth-portal/pkg/ui"
	"github.com/greenpau/go-identity"
	"go.uber.org/zap"
	"os"
	"strings"
	"sync"
)

var defaultTheme string = "basic"

// AuthPortalPool provides access to all instances of the plugin.
type AuthPortalPool struct {
	mu               sync.Mutex
	Members          []*AuthPortal
	RefMembers       map[string]*AuthPortal
	PrimaryInstances map[string]*AuthPortal
	MemberCount      int
}

// Register registers authentication provider instance with the pool.
func (p *AuthPortalPool) Register(m *AuthPortal) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if m.Name == "" {
		p.MemberCount++
		m.Name = fmt.Sprintf("portal-%d", p.MemberCount)
	}
	if p.RefMembers == nil {
		p.RefMembers = make(map[string]*AuthPortal)
	}
	if _, exists := p.RefMembers[m.Name]; !exists {
		p.RefMembers[m.Name] = m
		p.Members = append(p.Members, m)
	}
	if m.Context == "" {
		m.Context = "default"
	}
	if p.PrimaryInstances == nil {
		p.PrimaryInstances = make(map[string]*AuthPortal)
	}
	if m.PrimaryInstance {
		if _, exists := p.PrimaryInstances[m.Context]; exists {
			// The time different check is necessary to determine whether this is a configuration
			// load or reload. Typically, the provisioning of a plugin would happen in a second.
			timeDiff := m.startedAt.Sub(p.PrimaryInstances[m.Context].startedAt).Milliseconds()
			if timeDiff < 1000 {
				return fmt.Errorf(
					"found more than one primary instance of the plugin for %s context: %v, %v",
					m.Context, p.PrimaryInstances, timeDiff,
				)
			}
		}
		p.PrimaryInstances[m.Context] = m
	}

	if m.PrimaryInstance {
		if m.AuthURLPath == "" {
			return fmt.Errorf("%s: auth_url_path must be set", m.Name)
		}

		m.logger.Debug(
			"Authentication URL found",
			zap.String("instance_name", m.Name),
			zap.String("auth_url_path", m.AuthURLPath),
		)

		if m.TokenProvider.TokenName == "" {
			m.TokenProvider.TokenName = "access_token"
		}
		m.logger.Info(
			"JWT token name found",
			zap.String("instance_name", m.Name),
			zap.String("token_name", m.TokenProvider.TokenName),
		)

		if m.TokenProvider.TokenSecret == "" {
			if os.Getenv("JWT_TOKEN_SECRET") == "" {
				return fmt.Errorf("%s: token_secret must be defined either "+
					"via JWT_TOKEN_SECRET environment variable or "+
					"via token_secret configuration element",
					m.Name,
				)
			}
			m.TokenProvider.TokenSecret = os.Getenv("JWT_TOKEN_SECRET")
		}

		if m.TokenProvider.TokenIssuer == "" {
			m.logger.Warn(
				"JWT token issuer not found, using default",
				zap.String("instance_name", m.Name),
			)
			m.TokenProvider.TokenIssuer = "localhost"
		}

		if m.TokenProvider.TokenOrigin == "" {
			m.logger.Warn(
				"JWT token origin not found, using default",
				zap.String("instance_name", m.Name),
			)
			m.TokenProvider.TokenOrigin = "localhost"
		}

		m.logger.Debug(
			"JWT token origin found",
			zap.String("instance_name", m.Name),
			zap.String("token_origin", m.TokenProvider.TokenOrigin),
		)

		m.logger.Debug(
			"JWT token issuer found",
			zap.String("instance_name", m.Name),
			zap.String("token_issuer", m.TokenProvider.TokenIssuer),
		)

		if m.TokenProvider.TokenLifetime == 0 {
			m.logger.Warn(
				"JWT token lifetime not found, using default",
				zap.String("instance_name", m.Name),
			)
			m.TokenProvider.TokenLifetime = 900
		}
		m.logger.Debug(
			"JWT token lifetime found",
			zap.String("instance_name", m.Name),
			zap.Int("token_lifetime", m.TokenProvider.TokenLifetime),
		)

		m.logger.Debug(
			"JWT token configuration provisioned",
			zap.String("instance_name", m.Name),
			zap.String("auth_url_path", m.AuthURLPath),
			zap.String("token_name", m.TokenProvider.TokenName),
			zap.String("token_origin", m.TokenProvider.TokenOrigin),
			zap.String("token_issuer", m.TokenProvider.TokenIssuer),
			zap.Int("token_lifetime", m.TokenProvider.TokenLifetime),
		)

		// Backend Validation
		if len(m.Backends) == 0 {
			return fmt.Errorf("%s: no valid backend found", m.Name)
		}

		backendNameRef := make(map[string]interface{})

		m.loginOptions = make(map[string]interface{})
		m.loginOptions["form_required"] = "no"
		m.loginOptions["realm_dropdown_required"] = "no"
		m.loginOptions["username_required"] = "no"
		m.loginOptions["password_required"] = "no"
		m.loginOptions["external_providers_required"] = "no"
		m.loginOptions["registration_required"] = "no"
		m.loginOptions["password_recovery_required"] = "yes"
		var loginRealms []map[string]string
		var externalLoginProviders []map[string]string
		for _, backend := range m.Backends {
			backendName := backend.GetName()
			if backendName == "" {
				return fmt.Errorf("%s: backend name is required but missing", m.Name)
			}
			if _, exists := backendNameRef[backendName]; exists {
				return fmt.Errorf("%s: backend name %s is duplicate", m.Name, backendName)
			}
			backendNameRef[backendName] = true
			if err := backend.Configure(m); err != nil {
				return fmt.Errorf("%s: backend configuration error: %s", m.Name, err)
			}
			if err := backend.Validate(m); err != nil {
				return fmt.Errorf("%s: backend validation error: %s", m.Name, err)
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
				externalLoginProvider["endpoint"] = m.AuthURLPath + "/" + backendMethod + "/" + backendRealm
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
					externalLoginProvider["icon"] = "amazon"
					externalLoginProvider["text"] = "AWS"
					externalLoginProvider["color"] = "blue-grey darken-2"
				default:
					externalLoginProvider["icon"] = "shield"
					externalLoginProvider["text"] = backendRealm
					externalLoginProvider["color"] = "grey darken-3"
				}
				externalLoginProviders = append(externalLoginProviders, externalLoginProvider)
			}
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
			m.loginOptions["username_required"] = "yes"
			m.loginOptions["password_required"] = "yes"
		}
		if len(loginRealms) > 1 {
			m.loginOptions["realm_dropdown_required"] = "yes"
			m.loginOptions["realms"] = loginRealms

		}
		if len(externalLoginProviders) > 0 {
			m.loginOptions["external_providers_required"] = "yes"
			m.loginOptions["external_providers"] = externalLoginProviders
		}

		// Cookies Validation
		if m.Cookies == nil {
			m.Cookies = &cookies.Cookies{}
		}

		// Setup User Registration
		if m.UserRegistration == nil {
			m.UserRegistration = &registration.Registration{}
		}
		if m.UserRegistration.Title == "" {
			m.UserRegistration.Title = "Sign Up"
		}
		if m.UserRegistration.Dropbox == "" {
			m.UserRegistration.Disabled = true
		}

		if !m.UserRegistration.Disabled {
			m.loginOptions["registration_required"] = "yes"
			if m.UserRegistrationDatabase == nil {
				m.UserRegistrationDatabase = identity.NewDatabase()
				fileInfo, err := os.Stat(m.UserRegistration.Dropbox)
				if err != nil {
					if os.IsNotExist(err) {
						if err := m.UserRegistrationDatabase.SaveToFile(m.UserRegistration.Dropbox); err != nil {
							return fmt.Errorf("%s: registration dropbox setup failed: %s", m.Name, err)
						}
					} else {
						return fmt.Errorf("%s: registration dropbox metadata read failed: %s", m.Name, err)
					}
				} else {
					if fileInfo.IsDir() {
						return fmt.Errorf("%s: registration dropbox is a directory", m.Name)
					}
				}
				if err := m.UserRegistrationDatabase.LoadFromFile(m.UserRegistration.Dropbox); err != nil {
					return fmt.Errorf("%s: registration dropbox load failed: %s", m.Name, err)
				}
			}
		}

		m.logger.Debug(
			"Provisioned registration endpoint",
			zap.String("instance_name", m.Name),
			zap.String("dropbox", m.UserRegistration.Dropbox),
		)

		// Setup User Interface
		if m.UserInterface == nil {
			m.UserInterface = &UserInterfaceParameters{}
		}

		if m.UserInterface.Templates == nil {
			m.UserInterface.Templates = make(map[string]string)
		}

		m.uiFactory = ui.NewUserInterfaceFactory()
		if m.UserInterface.Title == "" {
			m.uiFactory.Title = "Sign In"
		} else {
			m.uiFactory.Title = m.UserInterface.Title
		}

		if m.UserInterface.LogoURL != "" {
			m.uiFactory.LogoURL = m.UserInterface.LogoURL
			m.uiFactory.LogoDescription = m.UserInterface.LogoDescription
		}

		m.uiFactory.ActionEndpoint = m.AuthURLPath

		if len(m.UserInterface.PrivateLinks) > 0 {
			m.uiFactory.PrivateLinks = m.UserInterface.PrivateLinks
		}

		if len(m.UserInterface.Realms) > 0 {
			m.uiFactory.Realms = m.UserInterface.Realms
		}

		if m.UserInterface.Theme == "" {
			m.UserInterface.Theme = defaultTheme
		}
		if _, exists := ui.Themes[m.UserInterface.Theme]; !exists {
			return fmt.Errorf(
				"%s: UI settings validation error, theme %s does not exist",
				m.Name, m.UserInterface.Theme,
			)
		}

		m.logger.Debug(
			"Provisioned authentication user interface parameters",
			zap.String("instance_name", m.Name),
			zap.String("title", m.uiFactory.Title),
			zap.String("logo_url", m.uiFactory.LogoURL),
			zap.String("logo_description", m.uiFactory.LogoDescription),
			zap.Any("action_endpoint", m.uiFactory.ActionEndpoint),
			zap.Any("private_links", m.uiFactory.PrivateLinks),
			zap.Any("realms", m.uiFactory.Realms),
			zap.String("theme", m.UserInterface.Theme),
		)

		// User Interface Templates
		for k := range ui.PageTemplates {
			tmplNameParts := strings.SplitN(k, "/", 2)
			tmplTheme := tmplNameParts[0]
			tmplName := tmplNameParts[1]
			if tmplTheme != m.UserInterface.Theme {
				continue
			}
			if _, exists := m.UserInterface.Templates[tmplName]; !exists {
				m.logger.Debug(
					"Provisioning default authentication user interface templates",
					zap.String("instance_name", m.Name),
					zap.String("template_theme", tmplTheme),
					zap.String("template_name", tmplName),
				)
				if err := m.uiFactory.AddBuiltinTemplate(k); err != nil {
					return fmt.Errorf(
						"%s: UI settings validation error, failed loading built-in %s template from %s theme: %s",
						m.Name, tmplName, tmplTheme, err,
					)
				}
				m.uiFactory.Templates[tmplName] = m.uiFactory.Templates[k]
			}
		}

		for tmplName, tmplPath := range m.UserInterface.Templates {
			m.logger.Debug(
				"Provisioning non-default authentication user interface templates",
				zap.String("instance_name", m.Name),
				zap.String("template_name", tmplName),
				zap.String("template_path", tmplPath),
			)
			if err := m.uiFactory.AddTemplate(tmplName, tmplPath); err != nil {
				return fmt.Errorf(
					"%s: UI settings validation error, failed loading %s template from %s: %s",
					m.Name, tmplName, tmplPath, err,
				)
			}
		}

		m.TokenValidator = jwt.NewTokenValidator()
		tokenConfig := jwt.NewCommonTokenConfig()
		tokenConfig.TokenSecret = m.TokenProvider.TokenSecret
		m.TokenValidator.TokenConfigs = []*jwt.CommonTokenConfig{tokenConfig}
		if err := m.TokenValidator.ConfigureTokenBackends(); err != nil {
			return fmt.Errorf(
				"%s: token validator backend configuration failed: %s",
				m.Name, err,
			)
		}
		entry := jwt.NewAccessListEntry()
		entry.Allow()
		if err := entry.SetClaim("roles"); err != nil {
			return fmt.Errorf(
				"%s: default access list configuration error: %s",
				m.Name, err,
			)
		}
		for _, v := range []string{"anonymous", "guest", "*"} {
			if err := entry.AddValue(v); err != nil {
				return fmt.Errorf(
					"%s: default access list configuration error: %s",
					m.Name, err,
				)
			}
		}
		m.TokenValidator.AccessList = append(m.TokenValidator.AccessList, entry)
		m.logger.Info(
			"JWT token validator provisioned",
			zap.String("instance_name", m.Name),
			zap.Any("access_list", m.TokenValidator.AccessList),
		)

		m.TokenValidator.TokenSources = []string{"cookie", "header", "query"}
		m.Provisioned = true
	}
	return nil
}

// Provision provisions non-primary instances in an authentication context.
func (p *AuthPortalPool) Provision(name string) error {
	if name == "" {
		return fmt.Errorf("authentication provider name is empty")
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.RefMembers == nil {
		return fmt.Errorf("no member reference found")
	}
	m, exists := p.RefMembers[name]
	if !exists {
		return fmt.Errorf("authentication provider %s not found", name)
	}
	if m == nil {
		return fmt.Errorf("authentication provider %s is nil", name)
	}
	if m.Provisioned {
		return nil
	}
	if m.Context == "" {
		m.Context = "default"
	}
	primaryInstance, primaryInstanceExists := p.PrimaryInstances[m.Context]
	if !primaryInstanceExists {
		m.ProvisionFailed = true
		return fmt.Errorf("no primary authentication provider found in %s context when configuring %s", m.Context, name)
	}

	if m.AuthURLPath == "" {
		m.AuthURLPath = primaryInstance.AuthURLPath
	}

	if m.TokenProvider == nil {
		m.TokenProvider = jwt.NewTokenProviderConfig()
	}

	if m.TokenProvider.TokenName == "" {
		m.TokenProvider.TokenName = primaryInstance.TokenProvider.TokenName
	}

	if m.TokenProvider.TokenSecret == "" {
		m.TokenProvider.TokenSecret = primaryInstance.TokenProvider.TokenSecret
	}

	if m.TokenProvider.TokenIssuer == "" {
		m.TokenProvider.TokenIssuer = primaryInstance.TokenProvider.TokenIssuer
	}

	if m.TokenProvider.TokenOrigin == "" {
		m.TokenProvider.TokenOrigin = primaryInstance.TokenProvider.TokenOrigin
	}

	if m.TokenProvider.TokenLifetime == 0 {
		m.TokenProvider.TokenLifetime = primaryInstance.TokenProvider.TokenLifetime
	}

	m.logger.Debug(
		"JWT token configuration provisioned",
		zap.String("instance_name", m.Name),
		zap.String("auth_url_path", m.AuthURLPath),
		zap.String("token_name", m.TokenProvider.TokenName),
		zap.String("token_origin", m.TokenProvider.TokenOrigin),
		zap.String("token_issuer", m.TokenProvider.TokenIssuer),
		zap.Int("token_lifetime", m.TokenProvider.TokenLifetime),
	)

	// Backend Validation
	if len(m.Backends) == 0 {
		m.Backends = primaryInstance.Backends
	} else {
		backendNameRef := make(map[string]interface{})
		for _, backend := range m.Backends {
			backendName := backend.GetName()
			if backendName == "" {
				return fmt.Errorf("%s: backend name is required but missing", m.Name)
			}
			if _, exists := backendNameRef[backendName]; exists {
				return fmt.Errorf("%s: backend name %s is duplicate", m.Name, backendName)
			}
			backendNameRef[backendName] = true
			if err := backend.Configure(m); err != nil {
				return fmt.Errorf("%s: backend configuration error: %s", m.Name, err)
			}
			if err := backend.Validate(m); err != nil {
				return fmt.Errorf("%s: backend validation error: %s", m.Name, err)
			}
			m.logger.Debug(
				"Provisioned authentication backend",
				zap.String("instance_name", m.Name),
				zap.String("backend_name", backendName),
				zap.String("backend_type", backend.authMethod),
			)
		}
	}

	// Cookies Validation
	if m.Cookies == nil {
		m.Cookies = &cookies.Cookies{}
	}

	// Setup User Registration
	m.UserRegistration = primaryInstance.UserRegistration
	m.UserRegistrationDatabase = primaryInstance.UserRegistrationDatabase

	// User Interface Settings
	if m.UserInterface == nil {
		m.UserInterface = &UserInterfaceParameters{}
	}

	if m.UserInterface.Templates == nil {
		m.UserInterface.Templates = primaryInstance.UserInterface.Templates
	}

	if m.UserInterface.Templates == nil {
		m.UserInterface.Templates = make(map[string]string)
	}

	m.uiFactory = ui.NewUserInterfaceFactory()
	if m.UserInterface.Title == "" {
		m.uiFactory.Title = primaryInstance.uiFactory.Title
	} else {
		m.uiFactory.Title = m.UserInterface.Title
	}

	if m.UserInterface.LogoURL == "" {
		m.uiFactory.LogoURL = primaryInstance.uiFactory.LogoURL
		m.uiFactory.LogoDescription = primaryInstance.uiFactory.LogoDescription
	} else {
		m.uiFactory.LogoURL = m.UserInterface.LogoURL
		m.uiFactory.LogoDescription = m.UserInterface.LogoDescription
	}

	m.uiFactory.ActionEndpoint = m.AuthURLPath

	if len(m.UserInterface.PrivateLinks) == 0 {
		m.UserInterface.PrivateLinks = primaryInstance.UserInterface.PrivateLinks
	}

	if len(m.UserInterface.PrivateLinks) > 0 {
		m.uiFactory.PrivateLinks = m.UserInterface.PrivateLinks
	}

	if len(m.UserInterface.Realms) == 0 {
		m.uiFactory.Realms = primaryInstance.UserInterface.Realms
	}

	if len(m.UserInterface.Realms) > 0 {
		m.uiFactory.Realms = m.UserInterface.Realms
	}

	m.logger.Debug(
		"Provisioned authentication user interface parameters for non-primaryInstance instance",
		zap.String("instance_name", m.Name),
		zap.String("title", m.uiFactory.Title),
		zap.String("logo_url", m.uiFactory.LogoURL),
		zap.String("logo_description", m.uiFactory.LogoDescription),
		zap.Any("action_endpoint", m.uiFactory.ActionEndpoint),
		zap.Any("private_links", m.uiFactory.PrivateLinks),
		zap.Any("realms", m.uiFactory.Realms),
	)

	// User Interface Templates
	if m.UserInterface.Theme == "" {
		m.UserInterface.Theme = primaryInstance.UserInterface.Theme
	}
	if _, exists := ui.Themes[m.UserInterface.Theme]; !exists {
		return fmt.Errorf(
			"%s: UI settings validation error, theme %s does not exist",
			m.Name, m.UserInterface.Theme,
		)
	}

	for k := range ui.PageTemplates {
		tmplNameParts := strings.SplitN(k, "/", 2)
		tmplTheme := tmplNameParts[0]
		tmplName := tmplNameParts[1]
		if tmplTheme != m.UserInterface.Theme {
			continue
		}
		if _, exists := m.UserInterface.Templates[tmplName]; !exists {
			m.logger.Debug(
				"Provisioning default authentication user interface templates",
				zap.String("instance_name", m.Name),
				zap.String("template_theme", tmplTheme),
				zap.String("template_name", tmplName),
			)
			if err := m.uiFactory.AddBuiltinTemplate(k); err != nil {
				return fmt.Errorf(
					"%s: UI settings validation error, failed loading built-in %s template from %s theme: %s",
					m.Name, tmplName, tmplTheme, err,
				)
			}
			m.uiFactory.Templates[tmplName] = m.uiFactory.Templates[k]
		}
	}

	for tmplName, tmplPath := range m.UserInterface.Templates {
		m.logger.Debug(
			"Provisioning non-default authentication user interface templates",
			zap.String("instance_name", m.Name),
			zap.String("template_name", tmplName),
			zap.String("template_path", tmplPath),
		)
		if err := m.uiFactory.AddTemplate(tmplName, tmplPath); err != nil {
			return fmt.Errorf(
				"%s: UI settings validation error, failed loading %s template from %s: %s",
				m.Name, tmplName, tmplPath, err,
			)
		}
	}

	// JWT Token Validator
	m.TokenValidator = jwt.NewTokenValidator()
	tokenConfig := jwt.NewCommonTokenConfig()
	tokenConfig.TokenSecret = m.TokenProvider.TokenSecret
	m.TokenValidator.TokenConfigs = []*jwt.CommonTokenConfig{tokenConfig}
	if err := m.TokenValidator.ConfigureTokenBackends(); err != nil {
		return fmt.Errorf(
			"%s: token validator backend configuration failed: %s",
			m.Name, err,
		)
	}

	// JWT Access List
	entry := jwt.NewAccessListEntry()
	entry.Allow()
	if err := entry.SetClaim("roles"); err != nil {
		return fmt.Errorf(
			"%s: default access list configuration error: %s",
			m.Name, err,
		)
	}
	for _, v := range []string{"anonymous", "guest", "*"} {
		if err := entry.AddValue(v); err != nil {
			return fmt.Errorf(
				"%s: default access list configuration error: %s",
				m.Name, err,
			)
		}
	}
	m.TokenValidator.AccessList = append(m.TokenValidator.AccessList, entry)

	m.logger.Info(
		"JWT token validator provisioned successfully",
		zap.String("instance_name", m.Name),
		zap.Any("access_list", m.TokenValidator.AccessList),
	)

	m.TokenValidator.TokenSources = []string{"cookie", "header", "query"}

	// Wrap up
	m.Provisioned = true
	m.ProvisionFailed = false

	return nil
}
