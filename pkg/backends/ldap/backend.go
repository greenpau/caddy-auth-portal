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

package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-ldap/ldap"
	"github.com/greenpau/caddy-auth-jwt"
	"go.uber.org/zap"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	globalAuthenticator  *Authenticator
	emailRegexPattern    = regexp.MustCompile("^[a-zA-Z0-9.+\\._~-]{1,61}@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	usernameRegexPattern = regexp.MustCompile("^[a-zA-Z0-9.+\\._~-]{1,61}$")
)

func init() {
	globalAuthenticator = NewAuthenticator()
	return
}

// UserGroup represent the binding between BaseDN and a serarch filter.
// Upon successful authentation for the combination, a user gets
// assigned the roles associated with the binding.
type UserGroup struct {
	GroupDN string   `json:"dn,omitempty"`
	Roles   []string `json:"roles,omitempty"`
}

// AuthServer represents an instance of LDAP server.
type AuthServer struct {
	Address          string   `json:"addr,omitempty"`
	URL              *url.URL `json:"-"`
	Port             string   `json:"-"`
	IgnoreCertErrors bool     `json:"ignore_cert_errors,omitempty"`
	Timeout          int      `json:"timeout,omitempty"`
}

// UserAttributes represent the mapping of LDAP attributes
// to JWT fields.
type UserAttributes struct {
	Name     string `json:"name,omitempty"`
	Surname  string `json:"surname,omitempty"`
	Username string `json:"username,omitempty"`
	MemberOf string `json:"member_of,omitempty"`
	Email    string `json:"email,omitempty"`
}

// Backend represents authentication provider with LDAP backend.
type Backend struct {
	Name               string                 `json:"name,omitempty"`
	Method             string                 `json:"method,omitempty"`
	Realm              string                 `json:"realm,omitempty"`
	Servers            []AuthServer           `json:"servers,omitempty"`
	BindUsername       string                 `json:"username,omitempty"`
	BindPassword       string                 `json:"password,omitempty"`
	Attributes         UserAttributes         `json:"attributes,omitempty"`
	SearchBaseDN       string                 `json:"search_base_dn,omitempty"`
	SearchFilter       string                 `json:"search_filter,omitempty"`
	Groups             []UserGroup            `json:"groups,omitempty"`
	TrustedAuthorities []string               `json:"trusted_authorities,omitempty"`
	TokenProvider      *jwt.CommonTokenConfig `json:"-"`
	Authenticator      *Authenticator         `json:"-"`
	logger             *zap.Logger
}

// NewDatabaseBackend return an instance of authentication provider
// with LDAP backend.
func NewDatabaseBackend() *Backend {
	b := &Backend{
		Method:        "ldap",
		TokenProvider: jwt.NewCommonTokenConfig(),
		Authenticator: globalAuthenticator,
	}
	return b
}

// Authenticator represents database connector.
type Authenticator struct {
	mux            sync.Mutex
	realm          string
	servers        []*AuthServer
	username       string
	password       string
	searchBaseDN   string
	searchFilter   string
	userAttributes UserAttributes
	rootCAs        *x509.CertPool
	groups         []*UserGroup
	logger         *zap.Logger
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
func (sa *Authenticator) ConfigureServers(servers []AuthServer) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	if len(servers) == 0 {
		return fmt.Errorf("no authentication servers found")
	}
	for _, entry := range servers {
		if !strings.HasPrefix(entry.Address, "ldaps://") {
			return fmt.Errorf("the server address does not have ldaps:// prefix, address: %s", entry.Address)
		}
		if entry.Timeout == 0 {
			entry.Timeout = 5
		}
		if entry.Timeout > 10 {
			return fmt.Errorf("invalid timeout value: %d, cannot exceed 10 seconds", entry.Timeout)
		}

		server := &AuthServer{
			Address:          entry.Address,
			IgnoreCertErrors: entry.IgnoreCertErrors,
			Timeout:          entry.Timeout,
		}

		url, err := url.Parse(entry.Address)
		if err != nil {
			return fmt.Errorf("failed parsing LDAP server address: %s, %s", entry.Address, err)
		}
		server.URL = url
		if server.URL.Port() == "" {
			server.Port = "636"
		} else {
			server.Port = server.URL.Port()
		}

		sa.logger.Info(
			"LDAP plugin configuration",
			zap.String("phase", "servers"),
			zap.String("address", server.Address),
			zap.String("url", server.URL.String()),
			zap.String("port", server.Port),
			zap.Bool("ignore_cert_errors", server.IgnoreCertErrors),
			zap.Int("timeout", server.Timeout),
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

	if strings.HasPrefix(password, "file:") {
		secretFile := strings.TrimPrefix(password, "file:")
		sa.logger.Info(
			"LDAP plugin configuration",
			zap.String("phase", "bind_credentials"),
			zap.String("password_file", secretFile),
		)
		fileContent, err := ioutil.ReadFile(secretFile)
		if err != nil {
			return fmt.Errorf("failed reading password file: %s, %s", secretFile, err)
		}
		password = strings.TrimSpace(string(fileContent))
		if password == "" {
			return fmt.Errorf("no password found in file: %s", secretFile)
		}
	}

	sa.username = username
	sa.password = password

	sa.logger.Info(
		"LDAP plugin configuration",
		zap.String("phase", "bind_credentials"),
		zap.String("username", sa.username),
	)
	return nil
}

// ConfigureSearch configures base DN, search filter, attributes for LDAP queries.
func (sa *Authenticator) ConfigureSearch(attr UserAttributes, searchBaseDN string, searchFilter string) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	if searchBaseDN == "" {
		return fmt.Errorf("no search_base_dn found")
	}
	if searchFilter == "" {
		searchFilter = "(&(|(sAMAccountName=%s)(mail=%s))(objectclass=user))"
	}
	if attr.Name == "" {
		attr.Name = "givenName"
	}
	if attr.Surname == "" {
		attr.Surname = "sn"
	}
	if attr.Username == "" {
		attr.Username = "sAMAccountName"
	}
	if attr.MemberOf == "" {
		attr.MemberOf = "memberOf"
	}
	if attr.Email == "" {
		attr.Email = "mail"
	}
	sa.logger.Info(
		"LDAP plugin configuration",
		zap.String("phase", "search"),
		zap.String("search_base_dn", searchBaseDN),
		zap.String("search_filter", searchFilter),
		zap.String("attr.name", attr.Name),
		zap.String("attr.surname", attr.Surname),
		zap.String("attr.username", attr.Username),
		zap.String("attr.member_of", attr.MemberOf),
		zap.String("attr.email", attr.Email),
	)
	sa.searchBaseDN = searchBaseDN
	sa.searchFilter = searchFilter
	sa.userAttributes = attr
	return nil
}

// ConfigureUserGroups configures user group bindings for LDAP searching.
func (sa *Authenticator) ConfigureUserGroups(groups []UserGroup) error {
	if len(groups) == 0 {
		return fmt.Errorf("no groups found")
	}
	for i, group := range groups {
		if group.GroupDN == "" {
			return fmt.Errorf("Base DN for group %d is empty", i)
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
			GroupDN: group.GroupDN,
			Roles:   group.Roles,
		}
		sa.logger.Info(
			"LDAP plugin configuration",
			zap.String("phase", "user_groups"),
			zap.String("roles", strings.Join(saGroup.Roles, ", ")),
			zap.String("dn", saGroup.GroupDN),
		)
		sa.groups = append(sa.groups, saGroup)
	}
	return nil
}

// AuthenticateUser checks the database for the presence of a username/email
// and password and returns user claims.
func (sa *Authenticator) AuthenticateUser(userInput, passwordInput string) (*jwt.UserClaims, int, error) {
	sa.mux.Lock()
	defer sa.mux.Unlock()

	for _, server := range sa.servers {
		timeout := time.Duration(server.Timeout) * time.Second

		tlsConfig := &tls.Config{
			InsecureSkipVerify: server.IgnoreCertErrors,
		}
		if sa.rootCAs != nil {
			tlsConfig.RootCAs = sa.rootCAs
		}

		ldapDialer, err := tls.DialWithDialer(
			&net.Dialer{
				Timeout: timeout,
			},
			"tcp",
			net.JoinHostPort(server.URL.Hostname(), server.Port),
			tlsConfig,
		)
		if err != nil {
			sa.logger.Error(
				"LDAP TLS dialer failed",
				zap.String("server", server.Address),
				zap.String("error", err.Error()),
			)
			continue
		}

		sa.logger.Debug(
			"LDAP TLS dialer setup succeeded",
			zap.String("server", server.Address),
		)

		ldapConnection := ldap.NewConn(ldapDialer, true)
		if ldapConnection == nil {
			sa.logger.Error(
				"LDAP connection failed",
				zap.String("server", server.Address),
				zap.String("error", err.Error()),
			)
			continue
		}
		// defer ldapConnection.Close()

		tlsState, ok := ldapConnection.TLSConnectionState()

		if !ok {
			sa.logger.Error(
				"LDAP connection TLS state polling failed",
				zap.String("server", server.Address),
				zap.String("error", "TLSConnectionState is not ok"),
			)
			continue
		}

		sa.logger.Debug(
			"LDAP connection TLS state polling succeeded",
			zap.String("server", server.Address),
			zap.String("server_name", tlsState.ServerName),
			zap.Bool("handshake_complete", tlsState.HandshakeComplete),
			zap.String("version", fmt.Sprintf("%d", tlsState.Version)),
			zap.String("negotiated_protocol", tlsState.NegotiatedProtocol),
		)

		ldapConnection.Start()
		defer ldapConnection.Close()

		if err := ldapConnection.Bind(sa.username, sa.password); err != nil {
			sa.logger.Error(
				"LDAP connection binding failed",
				zap.String("server", server.Address),
				zap.String("username", sa.username),
				zap.String("error", err.Error()),
			)
			continue
		}

		sa.logger.Debug(
			"LDAP binding succeeded",
			zap.String("server", server.Address),
		)

		searchFilter := strings.ReplaceAll(sa.searchFilter, "%s", userInput)

		req := ldap.NewSearchRequest(
			// group.GroupDN,
			sa.searchBaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			server.Timeout,
			false,
			searchFilter,
			[]string{
				sa.userAttributes.Name,
				sa.userAttributes.Surname,
				sa.userAttributes.Username,
				sa.userAttributes.MemberOf,
				sa.userAttributes.Email,
			},
			nil, // Controls
		)

		if req == nil {
			sa.logger.Error(
				"LDAP request building failed, request is nil",
				zap.String("server", server.Address),
				zap.String("search_base_dn", sa.searchBaseDN),
				zap.String("search_filter", searchFilter),
			)
			continue
		}

		resp, err := ldapConnection.Search(req)
		if err != nil {
			sa.logger.Error(
				"LDAP search failed",
				zap.String("server", server.Address),
				zap.String("search_base_dn", sa.searchBaseDN),
				zap.String("search_filter", searchFilter),
				zap.String("error", err.Error()),
			)
			continue
		}

		sa.logger.Debug(
			"LDAP search succeeded",
			zap.String("server", server.Address),
			zap.Int("entry_count", len(resp.Entries)),
			zap.String("search_base_dn", sa.searchBaseDN),
			zap.String("search_filter", searchFilter),
			zap.Any("users", resp.Entries),
		)

		if len(resp.Entries) == 0 {
			return nil, 401, fmt.Errorf("authentication failed")
		}

		if len(resp.Entries) > 1 {
			return nil, 401, fmt.Errorf("authentication failed, multiple users matched: %d", len(resp.Entries))
		}

		user := resp.Entries[0]
		var userFullName, userLastName, userFirstName, userAccountName, userMail string
		userRoles := make(map[string]bool)
		for _, attr := range user.Attributes {
			if len(attr.Values) < 1 {
				continue
			}
			if attr.Name == sa.userAttributes.Name {
				userFirstName = attr.Values[0]
			}
			if attr.Name == sa.userAttributes.Surname {
				userLastName = attr.Values[0]
			}
			if attr.Name == sa.userAttributes.Username {
				userAccountName = attr.Values[0]
			}
			if attr.Name == sa.userAttributes.MemberOf {
				for _, v := range attr.Values {
					for _, g := range sa.groups {
						if g.GroupDN != v {
							continue
						}
						for _, role := range g.Roles {
							if role == "" {
								continue
							}
							userRoles[role] = true
						}
					}
				}
			}
			if attr.Name == sa.userAttributes.Email {
				userMail = attr.Values[0]
			}
		}

		if userFirstName != "" {
			userFullName = userFirstName
		}
		if userLastName != "" {
			if userFullName == "" {
				userFullName = userLastName
			} else {
				userFullName = userFullName + " " + userLastName
			}
		}

		if len(userRoles) == 0 {
			return nil, 401, fmt.Errorf("authentication failed, no matched groups")
		}

		sa.logger.Debug(
			"LDAP user match",
			zap.String("server", server.Address),
			zap.String("name", userFullName),
			zap.String("username", userAccountName),
			zap.String("email", userMail),
			zap.Any("roles", userRoles),
		)

		if err := ldapConnection.Bind(user.DN, passwordInput); err != nil {
			sa.logger.Error(
				"LDAP auth binding failed",
				zap.String("server", server.Address),
				zap.String("username", user.DN),
				zap.String("error", err.Error()),
			)
			return nil, 401, fmt.Errorf("authentication failed, %s", err)
		}

		sa.logger.Debug(
			"LDAP connection is ready to be closed",
			zap.String("server", server.Address),
		)

		claims := &jwt.UserClaims{
			Subject: userAccountName,
		}
		if userFullName != "" {
			claims.Name = userFullName
		}
		if userMail != "" {
			claims.Email = userMail
		}
		for role := range userRoles {
			claims.Roles = append(claims.Roles, role)
		}
		//claims.Origin = sa.searchBaseDN
		claims.Origin = server.Address

		return claims, 200, nil
	}

	return nil, 400, fmt.Errorf("LDAP auth backends are unavailable")
}

// ConfigureTrustedAuthorities configured trusted certificate authorities, if any.
func (sa *Authenticator) ConfigureTrustedAuthorities(authorities []string) error {
	if len(authorities) == 0 {
		return nil
	}
	for _, authority := range authorities {
		pemCerts, err := ioutil.ReadFile(authority)
		if err != nil {
			return fmt.Errorf("failed reading trusted authority file: %s, %s", authority, err)
		}

		if sa.rootCAs == nil {
			sa.rootCAs = x509.NewCertPool()
		}
		if ok := sa.rootCAs.AppendCertsFromPEM(pemCerts); !ok {
			return fmt.Errorf("failed added trusted authority file contents to Root CA pool: %s", authority)
		}
		sa.logger.Debug(
			"added trusted authority",
			zap.String("pem_file", authority),
		)
	}
	return nil
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

	if err := b.Authenticator.ConfigureSearch(b.Attributes, b.SearchBaseDN, b.SearchFilter); err != nil {
		b.logger.Error("failed configuring base DN, search filter, attributes for LDAP queries",
			zap.String("error", err.Error()))
		return err
	}

	if err := b.Authenticator.ConfigureServers(b.Servers); err != nil {
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

	if err := b.Authenticator.ConfigureTrustedAuthorities(b.TrustedAuthorities); err != nil {
		b.logger.Error("failed configuring trusted authorities",
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
func (b *Backend) Authenticate(opts map[string]interface{}) (map[string]interface{}, error) {
	resp := make(map[string]interface{})
	resp["code"] = 400
	kv := opts["auth_credentials"].(map[string]string)
	if kv == nil {
		return resp, fmt.Errorf("No input to authenticate")
	}
	if _, exists := kv["username"]; !exists {
		return resp, fmt.Errorf("No username found")
	}
	if _, exists := kv["password"]; !exists {
		resp["code"] = 401
		return resp, fmt.Errorf("No password found")
	}
	if b.Authenticator == nil {
		resp["code"] = 500
		return resp, fmt.Errorf("LDAP backend is nil")
	}
	if kv["username"] == "" {
		return resp, fmt.Errorf("input username is empty")
	}
	if kv["password"] == "" {
		return resp, fmt.Errorf("input password is empty")
	}

	if !emailRegexPattern.MatchString(kv["username"]) && !usernameRegexPattern.MatchString(kv["username"]) {
		return resp, fmt.Errorf("input username fails regex validation")
	}

	claims, statusCode, err := b.Authenticator.AuthenticateUser(kv["username"], kv["password"])
	resp["code"] = statusCode
	if statusCode == 200 {
		if claims.Origin == "" {
			claims.Origin = b.TokenProvider.TokenOrigin
		}
		claims.ExpiresAt = time.Now().Add(time.Duration(b.TokenProvider.TokenLifetime) * time.Second).Unix()
		resp["claims"] = claims
		return resp, nil
	}
	return resp, err
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

// GetName return the name associated with this backend.
func (b *Backend) GetName() string {
	return b.Name
}

// ConfigureTokenProvider configures TokenProvider.
func (b *Backend) ConfigureTokenProvider(upstream *jwt.CommonTokenConfig) error {
	if upstream == nil {
		return fmt.Errorf("upstream token provider is nil")
	}
	if b.TokenProvider == nil {
		b.TokenProvider = jwt.NewCommonTokenConfig()
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
	b.TokenProvider.TokenLifetime = upstream.TokenLifetime
	b.TokenProvider.TokenName = upstream.TokenName
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

// GetMethod returns the authentication method associated with this backend.
func (b *Backend) GetMethod() string {
	return b.Method
}

// Do performs the requested operation.
func (b *Backend) Do(opts map[string]interface{}) error {
	op := opts["name"].(string)
	switch op {
	case "password_change":
		return fmt.Errorf("Password change operation is not available")
	}
	return fmt.Errorf("Unsupported backend operation")
}
