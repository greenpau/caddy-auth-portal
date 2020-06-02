package ldap

import (
	"fmt"
	"github.com/greenpau/caddy-auth-jwt"
	"go.uber.org/zap"
	"os"
	"strings"
	"sync"
	"time"
)

var globalAuthenticator *Authenticator

func init() {
	globalAuthenticator = NewAuthenticator()
	return
}

// UserGroup represent the binding between BaseDN and a serarch filter.
// Upon successful authentation for the combination, a user gets
// assigned the roles associated with the binding.
type UserGroup struct {
	BaseDN       string   `json:"base_dn,omitempty"`
	SearchFilter string   `json:"search_filter,omitempty"`
	Roles        []string `json:"roles,omitempty"`
}

// AuthServer represents an instance of LDAP server.
type AuthServer struct {
	Address          string `json:"-"`
	IgnoreCertErrors bool   `json:"-"`
	Timeout          int    `json:"-"`
}

// Backend represents authentication provider with SQLite backend.
type Backend struct {
	Realm            string                   `json:"realm,omitempty"`
	BindAddresses    []string                 `json:"addr,omitempty"`
	IgnoreCertErrors bool                     `json:"ignore_cert_errors,omitempty"`
	BindUsername     string                   `json:"username,omitempty"`
	BindPassword     string                   `json:"password,omitempty"`
	Groups           []UserGroup              `json:"groups,omitempty"`
	Timeout          int                      `json:"timeout,omitempty"`
	TokenProvider    *jwt.TokenProviderConfig `json:"jwt,omitempty"`
	Authenticator    *Authenticator           `json:"-"`
	logger           *zap.Logger
}

// NewDatabaseBackend return an instance of authentication provider
// with SQLite backend.
func NewDatabaseBackend() *Backend {
	b := &Backend{
		TokenProvider: jwt.NewTokenProviderConfig(),
		Authenticator: globalAuthenticator,
	}
	return b
}

// Authenticator represents database connector.
type Authenticator struct {
	mux      sync.Mutex
	realm    string
	servers  []*AuthServer
	username string
	password string
	groups   []*UserGroup
	logger   *zap.Logger
}

// NewAuthenticator returns an instance of Authenticator.
func NewAuthenticator() *Authenticator {
	return &Authenticator{
		servers: []*AuthServer{},
		groups:  []*UserGroup{},
	}
}

// ConfigureRealm configures a domain name (realm) associated with
// the instance of authenticator.
func (sa *Authenticator) ConfigureRealm(realm string) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	if realm == "" {
		return fmt.Errorf("no realm found")
	}
	sa.realm = realm
	sa.logger.Info(
		"LDAP plugin configuration",
		zap.String("phase", "realm"),
		zap.String("realm", realm),
	)
	return nil
}

// ConfigureServers configures the addresses of LDAP servers.
func (sa *Authenticator) ConfigureServers(addrs []string, ignoreCertErrors bool, timeout int) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	if len(addrs) == 0 {
		return fmt.Errorf("no addr found")
	}
	if timeout == 0 {
		timeout = 5
	}
	if timeout > 10 {
		return fmt.Errorf("invalid timeout value: %d", timeout)
	}
	for _, addr := range addrs {
		if !strings.HasPrefix(addr, "ldaps://") {
			return fmt.Errorf("the address does not have ldaps:// prefix, address: %s", addr)
		}
		server := &AuthServer{
			Address:          addr,
			IgnoreCertErrors: ignoreCertErrors,
			Timeout:          timeout,
		}
		sa.logger.Info(
			"LDAP plugin configuration",
			zap.String("phase", "servers"),
			zap.String("address", addr),
			zap.Bool("ignore_cert_errors", ignoreCertErrors),
			zap.Int("timeout", timeout),
		)
		sa.servers = append(sa.servers, server)
	}
	return nil
}

// ConfigureBindCredentials configures user credentials for LDAP binding.
func (sa *Authenticator) ConfigureBindCredentials(username, password string) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	if username == "" {
		return fmt.Errorf("no username found")
	}
	if password == "" {
		password = os.Getenv("LDAP_USER_SECRET")
		if password == "" {
			return fmt.Errorf("no password found")
		}
	}
	sa.username = username
	sa.password = password
	sa.logger.Info(
		"LDAP plugin configuration",
		zap.String("phase", "bind_credentials"),
		zap.String("username", username),
	)
	return nil
}

// ConfigureUserGroups configures user group bindings for LDAP searching.
func (sa *Authenticator) ConfigureUserGroups(groups []UserGroup) error {
	if len(groups) == 0 {
		return fmt.Errorf("no groups found")
	}
	for i, group := range groups {
		if group.BaseDN == "" {
			return fmt.Errorf("Base DN for group %d is empty", i)
		}
		if group.SearchFilter == "" {
			return fmt.Errorf("Search filter for group %d is empty", i)
		}
		if len(group.Roles) == 0 {
			return fmt.Errorf("Role assignments for group %d is empty", i)
		}
		for j, role := range group.Roles {
			if role == "" {
				return fmt.Errorf("Role assignment %d for group %d is empty", j, i)
			}
		}
		saGroup := &UserGroup{
			BaseDN:       group.BaseDN,
			SearchFilter: group.SearchFilter,
			Roles:        group.Roles,
		}
		sa.logger.Info(
			"LDAP plugin configuration",
			zap.String("phase", "user_groups"),
			zap.String("roles", strings.Join(saGroup.Roles, ", ")),
			zap.String("base_dn", saGroup.BaseDN),
			zap.String("search_filter", saGroup.SearchFilter),
		)
		sa.groups = append(sa.groups, saGroup)
	}
	return nil
}

// AuthenticateUser checks the database for the presence of a username/email
// and password and returns user claims.
func (sa *Authenticator) AuthenticateUser(userInput, password string) (*jwt.UserClaims, int, error) {
	// var err error
	sa.mux.Lock()
	defer sa.mux.Unlock()

	// TODO

	return nil, 400, fmt.Errorf("backend is still under development")
}

// ConfigureAuthenticator configures backend for .
func (b *Backend) ConfigureAuthenticator() error {
	if b.Authenticator == nil {
		b.Authenticator = NewAuthenticator()
	}

	b.Authenticator.logger = b.logger

	if err := b.Authenticator.ConfigureRealm(b.Realm); err != nil {
		b.logger.Error("failed configuring realm (domain) for LDAP authentication",
			zap.String("error", err.Error()))
		return err
	}

	if err := b.Authenticator.ConfigureServers(b.BindAddresses, b.IgnoreCertErrors, b.Timeout); err != nil {
		b.logger.Error("failed to configure LDAP server addresses",
			zap.String("error", err.Error()))
		return err
	}

	if err := b.Authenticator.ConfigureBindCredentials(b.BindUsername, b.BindPassword); err != nil {
		b.logger.Error("failed configuring user credentials for LDAP binding",
			zap.String("error", err.Error()))
		return err
	}

	if err := b.Authenticator.ConfigureUserGroups(b.Groups); err != nil {
		b.logger.Error("failed configuring user groups for LDAP search",
			zap.String("error", err.Error()))
		return err
	}

	return nil
}

// ValidateConfig checks whether Backend has mandatory configuration.
func (b *Backend) ValidateConfig() error {
	return nil
}

// Authenticate performs authentication.
func (b *Backend) Authenticate(reqID string, kv map[string]string) (*jwt.UserClaims, int, error) {
	if kv == nil {
		return nil, 400, fmt.Errorf("No input to authenticate")
	}
	if _, exists := kv["username"]; !exists {
		return nil, 400, fmt.Errorf("No username found")
	}
	if _, exists := kv["password"]; !exists {
		return nil, 401, fmt.Errorf("No password found")
	}
	if b.Authenticator == nil {
		return nil, 500, fmt.Errorf("LDAP backend is nil")
	}
	claims, statusCode, err := b.Authenticator.AuthenticateUser(kv["username"], kv["password"])
	if statusCode == 200 {
		claims.Origin = b.TokenProvider.TokenOrigin
		claims.ExpiresAt = time.Now().Add(time.Duration(b.TokenProvider.TokenLifetime) * time.Second).Unix()
		return claims, statusCode, nil
	}
	return nil, statusCode, err
}

// Validate checks whether Backend is functional.
func (b *Backend) Validate() error {
	if err := b.ValidateConfig(); err != nil {
		return err
	}
	if b.logger == nil {
		return fmt.Errorf("LDAP backend logger is nil")
	}

	b.logger.Info("validating LDAP backend")

	if b.Authenticator == nil {
		return fmt.Errorf("LDAP authenticator is nil")
	}

	b.logger.Info("successfully validated LDAP backend")
	return nil
}

// GetRealm return authentication realm.
func (b *Backend) GetRealm() string {
	return b.Realm
}

// ConfigureTokenProvider configures TokenProvider.
func (b *Backend) ConfigureTokenProvider(upstream *jwt.TokenProviderConfig) error {
	if upstream == nil {
		return fmt.Errorf("upstream token provider is nil")
	}
	if b.TokenProvider == nil {
		b.TokenProvider = jwt.NewTokenProviderConfig()
	}
	if b.TokenProvider.TokenName == "" {
		b.TokenProvider.TokenName = upstream.TokenName
	}
	if b.TokenProvider.TokenSecret == "" {
		b.TokenProvider.TokenSecret = upstream.TokenSecret
	}
	if b.TokenProvider.TokenIssuer == "" {
		b.TokenProvider.TokenIssuer = upstream.TokenIssuer
	}
	if b.TokenProvider.TokenOrigin == "" {
		b.TokenProvider.TokenOrigin = upstream.TokenOrigin
	}
	if b.TokenProvider.TokenLifetime == 0 {
		b.TokenProvider.TokenLifetime = upstream.TokenLifetime
	}
	return nil
}

// ConfigureLogger configures backend with the same logger as its user.
func (b *Backend) ConfigureLogger(logger *zap.Logger) error {
	if logger == nil {
		return fmt.Errorf("upstream logger is nil")
	}
	b.logger = logger
	return nil
}
