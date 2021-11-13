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

package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/greenpau/caddy-auth-portal/pkg/errors"
	"github.com/greenpau/go-identity/pkg/requests"
	"go.uber.org/zap"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

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
func (sa *Authenticator) ConfigureRealm(cfg *Config) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	if cfg.Realm == "" {
		return fmt.Errorf("no realm found")
	}
	sa.realm = cfg.Realm
	sa.logger.Info(
		"LDAP plugin configuration",
		zap.String("phase", "realm"),
		zap.String("realm", cfg.Realm),
	)
	return nil
}

// ConfigureServers configures the addresses of LDAP servers.
func (sa *Authenticator) ConfigureServers(cfg *Config) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	if len(cfg.Servers) == 0 {
		return fmt.Errorf("no authentication servers found")
	}
	for _, entry := range cfg.Servers {
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
func (sa *Authenticator) ConfigureBindCredentials(cfg *Config) error {
	username := cfg.BindUsername
	password := cfg.BindPassword
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
func (sa *Authenticator) ConfigureSearch(cfg *Config) error {
	attr := cfg.Attributes
	searchBaseDN := cfg.SearchBaseDN
	searchFilter := cfg.SearchFilter

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
func (sa *Authenticator) ConfigureUserGroups(cfg *Config) error {
	groups := cfg.Groups
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
func (sa *Authenticator) AuthenticateUser(r *requests.Request) error {
	// userInput, passwordInput string
	var roles []string
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

		searchFilter := strings.ReplaceAll(sa.searchFilter, "%s", r.User.Username)

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

		switch len(resp.Entries) {
		case 1:
		case 0:
			return errors.ErrBackendLdapAuthFailed.WithArgs("user not found")
		default:
			return errors.ErrBackendLdapAuthFailed.WithArgs("multiple users matched")
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
			return errors.ErrBackendLdapAuthFailed.WithArgs("no matched groups")
		}

		sa.logger.Debug(
			"LDAP user match",
			zap.String("server", server.Address),
			zap.String("name", userFullName),
			zap.String("username", userAccountName),
			zap.String("email", userMail),
			zap.Any("roles", userRoles),
		)

		if err := ldapConnection.Bind(user.DN, r.User.Password); err != nil {
			sa.logger.Error(
				"LDAP auth binding failed",
				zap.String("server", server.Address),
				zap.String("username", user.DN),
				zap.String("error", err.Error()),
			)
			return errors.ErrBackendLdapAuthFailed.WithArgs(err)
		}

		sa.logger.Debug(
			"LDAP connection is ready to be closed",
			zap.String("server", server.Address),
		)

		m := make(map[string]interface{})
		m["sub"] = userAccountName
		if userFullName != "" {
			m["name"] = userFullName
		}
		if userMail != "" {
			m["email"] = userMail
		}
		for role := range userRoles {
			roles = append(roles, role)
		}
		m["roles"] = roles
		// m["origin"] = sa.searchBaseDN
		m["origin"] = server.Address
		r.Response.Payload = m
		return nil
	}

	return errors.ErrBackendLdapAuthFailed.WithArgs("LDAP servers are unavailable")
}

// ConfigureTrustedAuthorities configured trusted certificate authorities, if any.
func (sa *Authenticator) ConfigureTrustedAuthorities(cfg *Config) error {
	authorities := cfg.TrustedAuthorities
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
