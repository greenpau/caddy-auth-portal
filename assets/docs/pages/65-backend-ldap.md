
## LDAP Authentication Backend

It is recommended reading the documentation for Local backend, because
it outlines important principles of operation of all backends.

Additionally, the LDAP backend works in conjunction with Local backend.
As you will see later, the two can be used together by introducing a
dropdown in UI interface to choose local versus LDAP domain authentication.

The reference configuration for the backend is `assets/conf/ldap/config.json`.

The following Caddy endpoint at `/auth` authentications users
from `contoso.com` domain.

There is a single LDAP server associated with the domain: `ldaps://ldaps.contoso.com`.

The plugin DOES NOT ignore certificate errors when connecting to the servers.
However, one may ignore the errors by setting `ignore_cert_errors` to `true`.

The LDAP attribute mapping to JWT fields is as follows.

| **JWT Token Field** | **LDAP Attribute** |
| --- | --- |
| `name` | `givenName` |
| `surname` | `sn` |
| `username` | `sAMAccountName` |
| `member_of` | `memberOf` |
| `email` | `mail` |

The plugin uses `authzsvc` domain user to perform LDAP bind.

The base search DN is `DC=CONTOSO,DC=COM`.

The plugin accepts username (`sAMAccountName`) or email address (`mail`)
and uses the following search filter: `(&(|(sAMAccountName=%s)(mail=%s))(objectclass=user))`.

For example:

```json
      {
        "Name": "sAMAccountName",
        "Values": [
          "jsmith"
        ]
      },
      {
        "Name": "mail",
        "Values": [
          "jsmith@contoso.com"
        ]
      }
```

Upon successful authentication, the plugin assign the following rules
to a user, provided the user is a member of a group:

| **JWT Role** | **LDAP Group Membership** |
| --- | --- |
| `admin` | `CN=Admins,OU=Security,OU=Groups,DC=CONTOSO,DC=COM` |
| `editor` | `CN=Editors,OU=Security,OU=Groups,DC=CONTOSO,DC=COM` |
| `viewer` | `CN=Viewers,OU=Security,OU=Groups,DC=CONTOSO,DC=COM` |

The security of the `password` could be improved by the following techniques:

* pass the password via environment variable `LDAP_USER_SECRET`
* store the password in a file and pass the file inside the `password`
  field with `file:` prefix, e.g. `file:/path/to/password`.

### Configuration Primer

The following `Caddyfile` secures Prometheus/Alertmanager services. Users may access
using local and LDAP credentials.

```
{
  http_port     8080
  https_port    8443
  debug
}

127.0.0.1:8443 {
  route /auth* {
    auth_portal {
      path /auth
      backends {
        local_backend {
          method local
          path assets/conf/local/auth/user_db.json
          realm local
        }
        ldap_backend {
          method ldap
          realm contoso.com
          servers {
            ldaps://ldaps.contoso.com ignore_cert_errors
          }
          attributes {
            name givenName
            surname sn
            username sAMAccountName
            member_of memberOf
            email mail
          }
          username "CN=authzsvc,OU=Service Accounts,OU=Administrative Accounts,DC=CONTOSO,DC=COM"
          password "P@ssW0rd123"
          search_base_dn "DC=CONTOSO,DC=COM"
          search_filter "(&(|(sAMAccountName=%s)(mail=%s))(objectclass=user))"
          groups {
            "CN=Admins,OU=Security,OU=Groups,DC=CONTOSO,DC=COM" admin
            "CN=Editors,OU=Security,OU=Groups,DC=CONTOSO,DC=COM" editor
            "CN=Viewers,OU=Security,OU=Groups,DC=CONTOSO,DC=COM" viewer
          }
        }
      }
      jwt {
        token_name access_token
        token_secret 0e2fdcf8-6868-41a7-884b-7308795fc286
        token_issuer e1008f2d-ccfa-4e62-bbe6-c202ec2988cc
      }
      ui {
        login_template "assets/ui/ldap/login.template"
        portal_template "assets/conf/local/ui/portal.template"
        logo_url "https://caddyserver.com/resources/images/caddy-circle-lock.svg"
        logo_description "Caddy"
        links {
          "Prometheus" /prometheus
          "Alertmanager" /alertmanager
          "My App" /myapp
        }
      }
    }
  }

  route /prometheus* {
    jwt {
      primary yes
      trusted_tokens {
        static_secret {
          token_name access_token
          token_secret 0e2fdcf8-6868-41a7-884b-7308795fc286
          token_issuer e1008f2d-ccfa-4e62-bbe6-c202ec2988cc
        }
      }
      auth_url /auth
      allow roles anonymous guest admin
      allow roles superadmin
      allow roles admin editor viewer
      allow roles AzureAD_Administrator AzureAD_Editor AzureAD_Viewer
    }
    uri strip_prefix /prometheus
    reverse_proxy http://127.0.0.1:9080
  }

  route /alertmanager* {
    jwt
    uri strip_prefix /alertmanager
    reverse_proxy http://127.0.0.1:9083
  }

  route /myapp* {
    jwt
    respond * "myapp" 200
  }

  route /version* {
    respond * "1.0.0" 200
  }

  route {
    redir https://{hostport}/auth 302
  }
}
```

The JSON representation is:

```json
{
  "match": [
    {
      "path": [
        "/auth*"
      ]
    }
  ],
  "handle": [
    {
      "handler": "authentication",
      "providers": {
        "portal": {
          "primary": true,
          "auth_url_path": "/auth",
          "backends": [
            {
              "method": "local",
              "path": "assets/backends/local/users.json",
              "realm": "local"
            },
            {
              "method": "ldap",
              "realm": "contoso.com",
              "servers": [
                {
                  "addr": "ldaps://ldaps.contoso.com",
                  "ignore_cert_errors": true
                }
              ],
              "attributes": {
                "name": "givenName",
                "surname": "sn",
                "username": "sAMAccountName",
                "member_of": "memberOf",
                "email": "mail"
              },
              "username": "CN=authzsvc,OU=Service Accounts,OU=Administrative Accounts,DC=CONTOSO,DC=COM",
              "password": "P@ssW0rd123",
              "search_base_dn": "DC=CONTOSO,DC=COM",
              "search_filter": "(&(|(sAMAccountName=%s)(mail=%s))(objectclass=user))",
              "groups": [
                {
                  "dn": "CN=Admins,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
                  "roles": [
                    "admin"
                  ]
                },
                {
                  "dn": "CN=Editors,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
                  "roles": [
                    "editor"
                  ]
                },
                {
                  "dn": "CN=Viewers,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
                  "roles": [
                    "viewer"
                  ]
                }
              ]
            }
          ],
          "jwt": {
            "token_secret": "383aca9a-1c39-4d7a-b4d8-67ba4718dd3f",
            "token_issuer": "7a50e023-2c6e-4a5e-913e-23ecd0e2b940"
          },
          "ui": {
            "templates": {
              "login": "assets/ui/ldap/login.template",
              "portal": "assets/ui/portal.template"
            },
            "logo_url": "https://caddyserver.com/resources/images/caddy-circle-lock.svg",
            "logo_description": "Caddy",
            "allow_role_selection": false,
            "auto_redirect_url": "",
            "private_links": [
              {
                "title": "Prometheus",
                "link": "/prometheus"
              },
              {
                "title": "Alertmanager",
                "link": "/alertmanager"
              }
            ]
          }
        }
      }
    }
  ],
  "terminal": true
}
```

### User Interface

Please notice that the `login` template uses different template
from the plain Local backend.

```
          "ui": {
            "templates": {
              "login": "assets/ui/ldap/login.template",
```

The reason for that is the introduction of a dropbox or an input
allowing a user to choose whether to use LDAP or Local backend
when authenticating.

For example, the following code adds an HTML input:

<img src="https://raw.githubusercontent.com/greenpau/caddy-auth-portal/main/assets/docs/images/login_form_domain_code.png">

The code is:

```html
                <div class="input-field">
                  <input id="realm" name="realm" type="text" class="validate">
                  <label for="realm">Domain</label>
                </div>
```

It results in having free form input box.

<img src="https://raw.githubusercontent.com/greenpau/caddy-auth-portal/main/assets/docs/images/login_form_domain_input.png">

A user may input the word `local` for Local backend and the
name of the domain for LDAP backend.

<table cellspacing="0" cellpadding="0" style="border-collapse: collapse; border: none; vertical-align: top;">
  <tr style="border: none;">
    <td style="border: none; vertical-align: top;">
      <img src="https://raw.githubusercontent.com/greenpau/caddy-auth-portal/main/assets/docs/images/login_form_domain_input_with_local.png">
    </td>
    <td style="border: none; vertical-align: top;">
      <img src="https://raw.githubusercontent.com/greenpau/caddy-auth-portal/main/assets/docs/images/login_form_domain_input_with_domain.png">
    </td>
  </tr>
</table>

The same could be accomplished with an HTML dropdown:

Add the following to the form:

```html
                <div class="input-field">
                  <label>Domain</label>
                  <br /><br />
                  <select id="realm" name="realm" class="browser-default">
                    <option value="local" selected>Local</option>
                    <option value="contoso.com">CONTOSO.COM</option>
                  </select>
                </div>
```

Additionally, add the following to `style`:

```css
      select {
        font-family: 'Roboto', sans-serif;
        color: #155D56;
      }
```

It results in having fixed dropdown box.

<img src="https://raw.githubusercontent.com/greenpau/caddy-auth-portal/main/assets/docs/images/login_form_dropdown_input.png">

### LDAP Authentication Process

The plugin does not keep connections open to LDAP servers. The plugin
tears a connection down each time it finishes authenticating a request
associated with the connection.

First, the plugin uses `username` and `password` to bind to an LDAP
server. The purpose of the connection is searching for user objects
in the server's directory.

The plugin takes the username provided in a request. Next, the
plugin substitutes `%s` with the username in its search filter, i.e.
`(&(|(sAMAccountName=%s)(mail=%s))(objectclass=user))`.

The plugin initiates a search for a user object in the scope provided
via `search_base_dn`, e.g. `DC=CONTOSO,DC=COM`.

If the number of objects in the result of the search is not `1`, then
authentication fails.

Typically, the response would have the following structure:

```json
[
  {
    "DN": "CN=Smith\\, John,OU=Users,DC=CONTOSO,DC=COM",
    "Attributes": [
      {
        "Name": "sn",
        "Values": [
          "Smith"
        ]
      },
      {
        "Name": "givenName",
        "Values": [
          "John"
        ]
      },
      {
        "Name": "memberOf",
        "Values": [
          "CN=Admins,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
          "CN=Editors,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
          "CN=Viewers,OU=Security,OU=Groups,DC=CONTOSO,DC=COM"
        ]
      },
      {
        "Name": "sAMAccountName",
        "Values": [
          "jsmith"
        ]
      },
      {
        "Name": "mail",
        "Values": [
          "jsmith@contoso.com"
        ]
      }
    ]
  }
]
```

The plugin iterates over `memberOf` attribute and compares the
values to its group mapping:

```json
              "groups": [
                {
                  "dn": "CN=Admins,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
                  "roles": [
                    "admin"
                  ]
                },
                {
                  "dn": "CN=Editors,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
                  "roles": [
                    "editor"
                  ]
                },
                {
                  "dn": "CN=Viewers,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
                  "roles": [
                    "viewer"
                  ]
                }
              ]
```

If there are no matches, the authentication fails.

Once the plugin determines the user's roles, e.g. `admin`, `editor`, `viewer`,
the plugin actually checks whether the user's password is valid.

It does so by doing LDAP re-binding with the user's DN and the password provided
in the request. In this example, the user's DN is
`CN=Smith\\, John,OU=Users,DC=CONTOSO,DC=COM`.

If the re-binding is successful, the plugin issues a JWT token.

[:arrow_up: Back to Top](#table-of-contents)

<!--- end of section -->