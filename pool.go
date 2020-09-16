package portal

import (
	"fmt"
	"go.uber.org/zap"
	"os"
	//"strings"
	"github.com/greenpau/caddy-auth-jwt"
	"github.com/greenpau/caddy-auth-portal/pkg/cookies"
	"github.com/greenpau/caddy-auth-ui"
	"sync"
)

var defaultPages = map[string]string{
	"login":  "forms_login",
	"portal": "forms_portal",
	"whoami": "forms_whoami",
}

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

		for _, backend := range m.Backends {
			if err := backend.Configure(m); err != nil {
				return fmt.Errorf("%s: backend configuration error: %s", m.Name, err)
			}
			if err := backend.Validate(m); err != nil {
				return fmt.Errorf("%s: backend validation error: %s", m.Name, err)
			}
			m.logger.Debug(
				"Provisioned authentication backend",
				zap.String("instance_name", m.Name),
				zap.String("backend_type", backend.authMethod),
			)
		}

		// Cookies Validation
		if m.Cookies == nil {
			m.Cookies = &cookies.Cookies{}
		}

		// Setup User Registration
		if m.UserRegistration == nil {
			m.UserRegistration = &UserRegistrationParameters{}
		}
		if m.UserRegistration.Title == "" {
			m.UserRegistration.Title = "Sign Up"
		}

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

		m.logger.Debug(
			"Provisioned authentication user interface parameters",
			zap.String("instance_name", m.Name),
			zap.String("title", m.uiFactory.Title),
			zap.String("logo_url", m.uiFactory.LogoURL),
			zap.String("logo_description", m.uiFactory.LogoDescription),
			zap.Any("action_endpoint", m.uiFactory.ActionEndpoint),
			zap.Any("private_links", m.uiFactory.PrivateLinks),
			zap.Any("realms", m.uiFactory.Realms),
		)

		// User Interface Templates
		for tmplName, tmplAlias := range defaultPages {
			if _, exists := m.UserInterface.Templates[tmplName]; !exists {
				m.logger.Debug(
					"Provisioning default authentication user interface templates",
					zap.String("instance_name", m.Name),
					zap.String("template_name", tmplName),
					zap.String("template_alias", tmplAlias),
				)
				if err := m.uiFactory.AddBuiltinTemplate(tmplAlias); err != nil {
					return fmt.Errorf(
						"%s: UI settings validation error, failed loading built-in %s (%s) template: %s",
						m.Name, tmplName, tmplAlias, err,
					)
				}
				m.uiFactory.Templates[tmplName] = m.uiFactory.Templates[tmplAlias]
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
		for _, backend := range m.Backends {
			if err := backend.Configure(m); err != nil {
				return fmt.Errorf("%s: backend configuration error: %s", m.Name, err)
			}
			if err := backend.Validate(m); err != nil {
				return fmt.Errorf("%s: backend validation error: %s", m.Name, err)
			}
			m.logger.Debug(
				"Provisioned authentication backend",
				zap.String("instance_name", m.Name),
				zap.String("backend_type", backend.authMethod),
			)
		}
	}

	// Cookies Validation
	if m.Cookies == nil {
		m.Cookies = &cookies.Cookies{}
	}

	// Setup User Registration
	if m.UserRegistration == nil {
		m.UserRegistration = &UserRegistrationParameters{}
	}
	if m.UserRegistration.Code == "" {
		m.UserRegistration.Code = primaryInstance.UserRegistration.Code
	}
	if m.UserRegistration.Title == "" {
		m.UserRegistration.Title = primaryInstance.UserRegistration.Title
	}

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
	for tmplName, tmplAlias := range defaultPages {
		if _, exists := m.UserInterface.Templates[tmplName]; !exists {
			m.logger.Debug(
				"Provisioning default authentication user interface templates",
				zap.String("instance_name", m.Name),
				zap.String("template_name", tmplName),
				zap.String("template_alias", tmplAlias),
			)
			if err := m.uiFactory.AddBuiltinTemplate(tmplAlias); err != nil {
				return fmt.Errorf(
					"%s: UI settings validation error, failed loading built-in %s (%s) template: %s",
					m.Name, tmplName, tmplAlias, err,
				)
			}
			m.uiFactory.Templates[tmplName] = m.uiFactory.Templates[tmplAlias]
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
