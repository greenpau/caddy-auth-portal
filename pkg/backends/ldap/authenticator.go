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
	mux               sync.Mutex
	realm             string
	servers           []*AuthServer
	username          string
	password          string
	searchBaseDN      string
	searchUserFilter  string
	searchGroupFilter string
	userAttributes    UserAttributes
	rootCAs           *x509.CertPool
	groups            []*UserGroup
	logger            *zap.Logger
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
		if !strings.HasPrefix(entry.Address, "ldaps://") && !strings.HasPrefix(entry.Address, "ldap://") {
			return fmt.Errorf("the server address does not have neither ldaps:// nor ldap:// prefix, address: %s", entry.Address)
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
			PosixGroups:      entry.PosixGroups,
		}

		url, err := url.Parse(entry.Address)
		if err != nil {
			return fmt.Errorf("failed parsing LDAP server address: %s, %s", entry.Address, err)
		}
		server.URL = url

		switch {
		case strings.HasPrefix(entry.Address, "ldaps://"):
			server.Port = "636"
			server.Encrypted = true
		case strings.HasPrefix(entry.Address, "ldap://"):
			server.Port = "389"
		}

		if server.URL.Port() != "" {
			server.Port = server.URL.Port()
		}

		sa.logger.Info(
			"LDAP plugin configuration",
			zap.String("phase", "servers"),
			zap.String("address", server.Address),
			zap.String("url", server.URL.String()),
			zap.String("port", server.Port),
			zap.Bool("ignore_cert_errors", server.IgnoreCertErrors),
			zap.Bool("posix_groups", server.PosixGroups),
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
	searchUserFilter := cfg.SearchUserFilter
	searchGroupFilter := cfg.SearchGroupFilter

	sa.mux.Lock()
	defer sa.mux.Unlock()
	if searchBaseDN == "" {
		return fmt.Errorf("no search_base_dn found")
	}
	if searchUserFilter == "" {
		searchUserFilter = "(&(|(sAMAccountName=%s)(mail=%s))(objectclass=user))"
	}
	if searchGroupFilter == "" {
		searchGroupFilter = "(&(uniqueMember=%s)(objectClass=groupOfUniqueNames))"
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
		zap.String("search_user_filter", searchUserFilter),
		zap.String("search_group_filter", searchGroupFilter),
		zap.String("attr.name", attr.Name),
		zap.String("attr.surname", attr.Surname),
		zap.String("attr.username", attr.Username),
		zap.String("attr.member_of", attr.MemberOf),
		zap.String("attr.email", attr.Email),
	)
	sa.searchBaseDN = searchBaseDN
	sa.searchUserFilter = searchUserFilter
	sa.searchGroupFilter = searchGroupFilter
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

// IdentifyUser returns user challenges.
func (sa *Authenticator) IdentifyUser(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()

	for _, server := range sa.servers {
		conn, err := sa.dial(server)
		if err != nil {
			continue
		}
		defer conn.Close()
		if err := sa.findUser(conn, server, r); err != nil {
			if err.Error() == errors.ErrBackendLdapAuthFailed.WithArgs("user not found").Error() {
				r.User.Username = "nobody"
				r.User.Email = "nobody@localhost"
				r.User.Challenges = []string{"password"}
				return nil
			}
			r.Response.Code = 401
			return err
		}

		return nil
	}
	r.Response.Code = 500
	return errors.ErrBackendLdapAuthFailed.WithArgs("LDAP servers are unavailable")
}

// AuthenticateUser checks the database for the presence of a username/email
// and password and returns user claims.
func (sa *Authenticator) AuthenticateUser(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()

	for _, server := range sa.servers {
		ldapConnection, err := sa.dial(server)
		if err != nil {
			continue
		}
		defer ldapConnection.Close()

		searchUserFilter := strings.ReplaceAll(sa.searchUserFilter, "%s", r.User.Username)

		req := ldap.NewSearchRequest(
			// group.GroupDN,
			sa.searchBaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			server.Timeout,
			false,
			searchUserFilter,
			[]string{
				sa.userAttributes.Email,
			},
			nil, // Controls
		)

		if req == nil {
			sa.logger.Error(
				"LDAP request building failed, request is nil",
				zap.String("server", server.Address),
				zap.String("search_base_dn", sa.searchBaseDN),
				zap.String("search_user_filter", searchUserFilter),
			)
			continue
		}

		resp, err := ldapConnection.Search(req)
		if err != nil {
			sa.logger.Error(
				"LDAP search failed",
				zap.String("server", server.Address),
				zap.String("search_base_dn", sa.searchBaseDN),
				zap.String("search_user_filter", searchUserFilter),
				zap.String("error", err.Error()),
			)
			continue
		}

		switch len(resp.Entries) {
		case 1:
		case 0:
			return errors.ErrBackendLdapAuthFailed.WithArgs("user not found")
		default:
			return errors.ErrBackendLdapAuthFailed.WithArgs("multiple users matched")
		}

		user := resp.Entries[0]
		// Use the provided password to make an LDAP connection.
		if err := ldapConnection.Bind(user.DN, r.User.Password); err != nil {
			sa.logger.Error(
				"LDAP auth binding failed",
				zap.String("server", server.Address),
				zap.String("dn", user.DN),
				zap.String("username", r.User.Username),
				zap.String("error", err.Error()),
			)
			return errors.ErrBackendLdapAuthFailed.WithArgs(err)
		}

		sa.logger.Debug(
			"LDAP auth succeeded",
			zap.String("server", server.Address),
			zap.String("dn", user.DN),
			zap.String("username", r.User.Username),
		)
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

func (sa *Authenticator) searchGroups(conn *ldap.Conn, reqData map[string]interface{}, roles map[string]bool) error {
	if roles == nil {
		roles = make(map[string]bool)
	}

	req := ldap.NewSearchRequest(reqData["base_dn"].(string), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0,
		reqData["timeout"].(int), false, reqData["search_group_filter"].(string), []string{"dn"}, nil,
	)
	if req == nil {
		return fmt.Errorf("failed building group search LDAP request")
	}

	resp, err := conn.Search(req)
	if err != nil {
		return err
	}

	if len(resp.Entries) < 1 {
		return fmt.Errorf("no groups found for %s", reqData["user_dn"].(string))
	}

	for _, entry := range resp.Entries {
		for _, g := range sa.groups {
			if g.GroupDN != entry.DN {
				continue
			}
			for _, role := range g.Roles {
				if role == "" {
					continue
				}
				roles[role] = true
			}
		}
	}
	return nil
}

func (sa *Authenticator) dial(server *AuthServer) (*ldap.Conn, error) {
	var ldapDialer net.Conn
	var err error
	timeout := time.Duration(server.Timeout) * time.Second
	if server.Encrypted {
		// Handle LDAPS servers.
		tlsConfig := &tls.Config{
			InsecureSkipVerify: server.IgnoreCertErrors,
		}
		if sa.rootCAs != nil {
			tlsConfig.RootCAs = sa.rootCAs
		}
		ldapDialer, err = tls.DialWithDialer(
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
			return nil, err
		}
		sa.logger.Debug(
			"LDAP TLS dialer setup succeeded",
			zap.String("server", server.Address),
		)
	} else {
		// Handle LDAP servers.
		ldapDialer, err = net.DialTimeout("tcp", net.JoinHostPort(server.URL.Hostname(), server.Port), timeout)
		if err != nil {
			sa.logger.Error(
				"LDAP dialer failed",
				zap.String("server", server.Address),
				zap.String("error", err.Error()),
			)
		}
		sa.logger.Debug(
			"LDAP dialer setup succeeded",
			zap.String("server", server.Address),
		)
	}

	ldapConnection := ldap.NewConn(ldapDialer, server.Encrypted)
	if ldapConnection == nil {
		sa.logger.Error(
			"LDAP connection failed",
			zap.String("server", server.Address),
			zap.String("error", err.Error()),
		)
		return nil, err
	}

	if server.Encrypted {
		tlsState, ok := ldapConnection.TLSConnectionState()
		if !ok {
			sa.logger.Error(
				"LDAP connection TLS state polling failed",
				zap.String("server", server.Address),
				zap.String("error", "TLSConnectionState is not ok"),
			)
			return nil, err
		}

		sa.logger.Debug(
			"LDAP connection TLS state polling succeeded",
			zap.String("server", server.Address),
			zap.String("server_name", tlsState.ServerName),
			zap.Bool("handshake_complete", tlsState.HandshakeComplete),
			zap.String("version", fmt.Sprintf("%d", tlsState.Version)),
			zap.String("negotiated_protocol", tlsState.NegotiatedProtocol),
		)
	}

	ldapConnection.Start()

	if err := ldapConnection.Bind(sa.username, sa.password); err != nil {
		sa.logger.Error(
			"LDAP connection binding failed",
			zap.String("server", server.Address),
			zap.String("username", sa.username),
			zap.String("error", err.Error()),
		)
		return nil, err
	}
	sa.logger.Debug(
		"LDAP binding succeeded",
		zap.String("server", server.Address),
	)
	return ldapConnection, nil
}

func (sa *Authenticator) findUser(ldapConnection *ldap.Conn, server *AuthServer, r *requests.Request) error {
	searchUserFilter := strings.ReplaceAll(sa.searchUserFilter, "%s", r.User.Username)

	req := ldap.NewSearchRequest(
		// group.GroupDN,
		sa.searchBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		server.Timeout,
		false,
		searchUserFilter,
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
			zap.String("search_user_filter", searchUserFilter),
		)
		return errors.ErrBackendLdapAuthFailed.WithArgs("LDAP request building failed, request is nil")
	}

	resp, err := ldapConnection.Search(req)
	if err != nil {
		sa.logger.Error(
			"LDAP search failed",
			zap.String("server", server.Address),
			zap.String("search_base_dn", sa.searchBaseDN),
			zap.String("search_user_filter", searchUserFilter),
			zap.String("error", err.Error()),
		)
		return errors.ErrBackendLdapAuthFailed.WithArgs("LDAP search failed")
	}

	sa.logger.Debug(
		"LDAP search succeeded",
		zap.String("server", server.Address),
		zap.Int("entry_count", len(resp.Entries)),
		zap.String("search_base_dn", sa.searchBaseDN),
		zap.String("search_user_filter", searchUserFilter),
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

	if server.PosixGroups {
		// Handle POSIX group memberships.
		searchGroupRequest := map[string]interface{}{
			"user_dn":             user.DN,
			"base_dn":             sa.searchBaseDN,
			"search_group_filter": strings.ReplaceAll(sa.searchGroupFilter, "%s", user.DN),
			"timeout":             server.Timeout,
		}
		if err := sa.searchGroups(ldapConnection, searchGroupRequest, userRoles); err != nil {
			sa.logger.Error(
				"LDAP group search failed, request",
				zap.String("server", server.Address),
				zap.String("base_dn", sa.searchBaseDN),
				zap.String("search_group_filter", sa.searchGroupFilter),
				zap.Error(err),
			)
			return err
		}
	}

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

	r.User.Username = userAccountName
	r.User.Email = userMail
	r.User.FullName = userFullName
	for role := range userRoles {
		r.User.Roles = append(r.User.Roles, role)
	}
	r.User.Challenges = []string{"password"}
	r.Response.Code = 200
	return nil
}
