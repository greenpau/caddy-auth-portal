package forms

import (
	"fmt"
	"go.uber.org/zap"
	"os"
	//"strings"
	"github.com/greenpau/caddy-auth-jwt"
	"github.com/greenpau/caddy-auth-ui"
	"sync"
)

// AuthProviderPool provides access to all instances of the plugin.
type AuthProviderPool struct {
	mu          sync.Mutex
	Members     []*AuthProvider
	RefMembers  map[string]*AuthProvider
	Masters     map[string]*AuthProvider
	MemberCount int
}

// Register registers authentication provider instance with the pool.
func (p *AuthProviderPool) Register(m *AuthProvider) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if m.Name == "" {
		p.MemberCount++
		m.Name = fmt.Sprintf("forms-%d", p.MemberCount)
	}
	if p.RefMembers == nil {
		p.RefMembers = make(map[string]*AuthProvider)
	}
	if _, exists := p.RefMembers[m.Name]; !exists {
		p.RefMembers[m.Name] = m
		p.Members = append(p.Members, m)
	}
	if m.Context == "" {
		m.Context = "default"
	}
	if p.Masters == nil {
		p.Masters = make(map[string]*AuthProvider)
	}
	if m.Master {
		if _, exists := p.Masters[m.Context]; exists {
			return fmt.Errorf("found more than one master instance of the plugin for %s context", m.Context)
		}
		p.Masters[m.Context] = m
	}

	if m.Master {
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
				zap.String("backend_type", backend.bt),
			)
		}

		// UI Validation
		uiPages := map[string]string{
			"login":  "forms_login",
			"portal": "forms_portal",
		}
		if m.UserInterface == nil {
			m.UserInterface = &UserInterfaceParameters{}
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

		m.logger.Debug(
			"Provisioned authentication user interface parameters",
			zap.String("instance_name", m.Name),
			zap.String("title", m.uiFactory.Title),
			zap.String("logo_url", m.uiFactory.LogoURL),
			zap.String("logo_description", m.uiFactory.LogoDescription),
			zap.Any("action_endpoint", m.uiFactory.ActionEndpoint),
			zap.Any("private_links", m.uiFactory.PrivateLinks),
		)

		for tmplName, tmplAlias := range uiPages {
			m.logger.Debug(
				"Provisioning authentication user interface templates",
				zap.String("instance_name", m.Name),
				zap.String("template_name", tmplName),
				zap.String("template_alias", tmplAlias),
			)
			useDefaultTemplate := false
			if m.UserInterface.Templates == nil {
				m.logger.Debug(
					"UI templates were not defined, using default template",
					zap.String("instance_name", m.Name),
				)
				useDefaultTemplate = true
			} else {
				if v, exists := m.UserInterface.Templates[tmplName]; !exists {
					m.logger.Debug(
						"UI template was not defined, using default template",
						zap.String("instance_name", m.Name),
						zap.String("template_name", tmplName),
					)
					useDefaultTemplate = true
				} else {
					m.logger.Debug(
						"UI template definition found",
						zap.String("instance_name", m.Name),
						zap.String("template_name", tmplName),
						zap.String("template_path", v),
					)
				}
			}

			if useDefaultTemplate {
				m.logger.Debug(
					fmt.Sprintf("adding UI template %s to UI factory", tmplAlias),
					zap.String("instance_name", m.Name),
				)
				if err := m.uiFactory.AddBuiltinTemplate(tmplAlias); err != nil {
					return fmt.Errorf(
						"%s: UI settings validation error, failed loading built-in %s (%s) template: %s",
						m.Name, tmplName, tmplAlias, err,
					)
				}
				m.uiFactory.Templates[tmplName] = m.uiFactory.Templates[tmplAlias]
				continue
			}

			if err := m.uiFactory.AddTemplate(tmplName, m.UserInterface.Templates[tmplName]); err != nil {
				return fmt.Errorf(
					"%s: UI settings validation error, failed loading template from %s: %s",
					m.Name, m.UserInterface.Templates[tmplName], err,
				)
			}
		}

		for tmplName := range m.UserInterface.Templates {
			if _, exists := uiPages[tmplName]; !exists {
				return fmt.Errorf(
					"%s: UI settings validation error, unsupported template type: %s",
					m.Name, tmplName,
				)
			}
		}

		m.TokenValidator = jwt.NewTokenValidator()
		m.TokenValidator.TokenSecret = m.TokenProvider.TokenSecret
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

		m.Provisioned = true
	}
	return nil
}

// Provision provisions non-master instances in an authentication context.
func (p *AuthProviderPool) Provision(name string) error {
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
	master, masterExists := p.Masters[m.Context]
	if !masterExists {
		m.ProvisionFailed = true
		return fmt.Errorf("no master authentication provider found in %s context when configuring %s", m.Context, name)
	}

	if m.AuthURLPath == "" {
		m.AuthURLPath = master.AuthURLPath
	}

	if m.TokenProvider == nil {
		m.TokenProvider = jwt.NewTokenProviderConfig()
	}

	if m.TokenProvider.TokenName == "" {
		m.TokenProvider.TokenName = master.TokenProvider.TokenName
	}

	if m.TokenProvider.TokenSecret == "" {
		m.TokenProvider.TokenSecret = master.TokenProvider.TokenSecret
	}

	if m.TokenProvider.TokenIssuer == "" {
		m.TokenProvider.TokenIssuer = master.TokenProvider.TokenIssuer
	}

	if m.TokenProvider.TokenOrigin == "" {
		m.TokenProvider.TokenOrigin = master.TokenProvider.TokenOrigin
	}

	if m.TokenProvider.TokenLifetime == 0 {
		m.TokenProvider.TokenLifetime = master.TokenProvider.TokenLifetime
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
		m.Backends = master.Backends
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
				zap.String("backend_type", backend.bt),
			)
		}
	}

	// User Interface Settings
	uiPages := map[string]string{
		"login":  "forms_login",
		"portal": "forms_portal",
	}
	if m.UserInterface == nil {
		m.UserInterface = &UserInterfaceParameters{}
	}

	m.uiFactory = ui.NewUserInterfaceFactory()
	if m.UserInterface.Title == "" {
		m.uiFactory.Title = master.uiFactory.Title
	} else {
		m.uiFactory.Title = m.UserInterface.Title
	}

	if m.UserInterface.LogoURL == "" {
		m.uiFactory.LogoURL = master.uiFactory.LogoURL
		m.uiFactory.LogoDescription = master.uiFactory.LogoDescription
	} else {
		m.uiFactory.LogoURL = m.UserInterface.LogoURL
		m.uiFactory.LogoDescription = m.UserInterface.LogoDescription
	}

	m.uiFactory.ActionEndpoint = m.AuthURLPath

	if len(m.UserInterface.PrivateLinks) == 0 {
		m.UserInterface.PrivateLinks = master.UserInterface.PrivateLinks
	}

	if len(m.UserInterface.PrivateLinks) > 0 {
		m.uiFactory.PrivateLinks = m.UserInterface.PrivateLinks
	}

	m.logger.Debug(
		"Provisioned authentication user interface parameters",
		zap.String("instance_name", m.Name),
		zap.String("title", m.uiFactory.Title),
		zap.String("logo_url", m.uiFactory.LogoURL),
		zap.String("logo_description", m.uiFactory.LogoDescription),
		zap.Any("action_endpoint", m.uiFactory.ActionEndpoint),
		zap.Any("private_links", m.uiFactory.PrivateLinks),
	)

	// User Interface Templates
	for tmplName, tmplAlias := range uiPages {
		m.logger.Debug(
			"Provisioning authentication user interface templates",
			zap.String("instance_name", m.Name),
			zap.String("template_name", tmplName),
			zap.String("template_alias", tmplAlias),
		)
		useDefaultTemplate := false
		if m.UserInterface.Templates == nil {
			m.logger.Debug(
				"UI templates were not defined, using default template",
				zap.String("instance_name", m.Name),
			)
			useDefaultTemplate = true
		} else {
			if v, exists := m.UserInterface.Templates[tmplName]; !exists {
				m.logger.Debug(
					"UI template was not defined, using default template",
					zap.String("instance_name", m.Name),
					zap.String("template_name", tmplName),
				)
				useDefaultTemplate = true
			} else {
				m.logger.Debug(
					"UI template definition found",
					zap.String("instance_name", m.Name),
					zap.String("template_name", tmplName),
					zap.String("template_path", v),
				)
			}
		}

		if useDefaultTemplate {
			m.logger.Debug(
				fmt.Sprintf("adding UI template %s to UI factory", tmplAlias),
				zap.String("instance_name", m.Name),
			)
			if err := m.uiFactory.AddBuiltinTemplate(tmplAlias); err != nil {
				return fmt.Errorf(
					"%s: UI settings validation error, failed loading built-in %s (%s) template: %s",
					m.Name, tmplName, tmplAlias, err,
				)
			}
			m.uiFactory.Templates[tmplName] = m.uiFactory.Templates[tmplAlias]
			continue
		}

		if err := m.uiFactory.AddTemplate(tmplName, m.UserInterface.Templates[tmplName]); err != nil {
			return fmt.Errorf(
				"%s: UI settings validation error, failed loading template from %s: %s",
				m.Name, m.UserInterface.Templates[tmplName], err,
			)
		}
	}

	for tmplName := range m.UserInterface.Templates {
		if _, exists := uiPages[tmplName]; !exists {
			return fmt.Errorf(
				"%s: UI settings validation error, unsupported template type: %s",
				m.Name, tmplName,
			)
		}
	}

	// JWT Token Validator
	m.TokenValidator = jwt.NewTokenValidator()
	m.TokenValidator.TokenSecret = m.TokenProvider.TokenSecret
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

	// Wrap up
	m.Provisioned = true
	m.ProvisionFailed = false

	return nil
}
