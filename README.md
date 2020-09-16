# caddy-auth-portal

<a href="https://github.com/greenpau/caddy-auth-portal/actions/" target="_blank"><img src="https://github.com/greenpau/caddy-auth-portal/workflows/build/badge.svg?branch=main"></a>
<a href="https://pkg.go.dev/github.com/greenpau/caddy-auth-portal" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
<a href="https://caddy.community" target="_blank"><img src="https://img.shields.io/badge/community-forum-ff69b4.svg"></a>

Authentication Plugin for [Caddy v2](https://github.com/caddyserver/caddy)
implementing Form-Based Authentication and Basic Authentication.

Please ask questions either here or via LinkedIn. I am happy to help you! @greenpau

<!-- begin-markdown-toc -->
## Table of Contents

* [Overview](#overview)
* [Authentication Portal](#authentication-portal)
* [Usage Examples](#usage-examples)
  * [Secure Prometheus](#secure-prometheus)
* [Authentication Methods](#authentication-methods)
  * [Basic Authentication](#basic-authentication)
  * [Form-Based Authentication](#form-based-authentication)
* [User Interface Features](#user-interface-features)
  * [Auto-Redirect URL](#auto-redirect-url)
* [Local Authentication Backend](#local-authentication-backend)
  * [Configuration Primer](#configuration-primer)
  * [Identity Store](#identity-store)
  * [Password Management](#password-management)
* [LDAP Authentication Backend](#ldap-authentication-backend)
  * [Configuration Primer](#configuration-primer-1)
  * [User Interface](#user-interface)
  * [LDAP Authentication Process](#ldap-authentication-process)

<!-- end-markdown-toc -->

## Overview

The purpose of this plugin is providing **authentication** only. The plugin
issue JWT tokens upon successful authentication. In turn, the **authorization**
of the tokens is being handled by [`caddy-auth-jwt`](https://github.com/greenpau/caddy-auth-jwt).

The plugin supports the following **authentication** backends:

* Local (`local`) - JSON flat file database
* LDAP (`ldap`) - remote Microsoft AD database

The plugin accepts user credentials for **authentication** with:

* Form-based Authentication: `POST` with `application/x-www-form-urlencoded`
* Basic Authentication: `GET` with `Authorization: Basic` header

The following digram is visual representation of the configuration of
[`caddy-auth-portal`](https://github.com/greenpau/caddy-auth-portal) and
[`caddy-auth-jwt`](https://github.com/greenpau/caddy-auth-jwt).

![Authentication Plugins](assets/docs/images/auth_plugin_arch.png)

## Authentication Portal

<table cellspacing="0" cellpadding="0" style="border-collapse: collapse; border: none; vertical-align: top;">
  <tr style="border: none;">
    <td style="border: none; vertical-align: top;">
      <img src="https://raw.githubusercontent.com/greenpau/caddy-auth-ui/main/assets/docs/_static/images/forms_login.png">
    </td>
    <td style="border: none; vertical-align: top;">
      <img src="https://raw.githubusercontent.com/greenpau/caddy-auth-ui/main/assets/docs/_static/images/forms_portal.png">
    </td>
  </tr>
</table>

The following `Caddyfile` settings define the scope of the cookies issued by
the plugin. Specifically, what URLs the cookies should be sent to.
See [MDN - Using HTTP cookies - Define where cookies are sent](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
for more information.

* `cookie_domain`: adds the **Domain** attribute to a cookie. It determines
  which hosts are allowed to receive the cookie.
* `cookie_path`: adds the **Path** attribute to a cookie. It determines the
  URL path that must exist in the requested URL in order to send
  the Cookie header.

## Usage Examples

### Secure Prometheus

The following `Caddyfile` secures Prometheus/Alertmanager services:

```Caddyfile
{
  http_port     8080
  https_port    8443
  debug
}

localhost:8443 {
  route /auth* {
    auth_portal {
      path /auth
      backends {
        local_backend {
          method local
          path /etc/gatekeeper/auth/local/users.json
          realm local
        }
      }
      jwt {
        token_name access_token
        token_secret 0e2fdcf8-6868-41a7-884b-7308795fc286
        token_issuer e1008f2d-ccfa-4e62-bbe6-c202ec2988cc
      }
      ui {
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

If you would like to style the UI differently, then specify your
templates and settings:

```
      ui {
        login_template "/etc/gatekeeper/ui/forms_login.template"
        portal_template "/etc/gatekeeper/ui/forms_portal.template"
        logo_url "https://caddyserver.com/resources/images/caddy-circle-lock.svg"
        logo_description "Caddy"
        links {
          "Prometheus" /prometheus
          "Alertmanager" /alertmanager
          "My App" /myapp
        }
      }
```

In fact, if you are not going to display any links, then
remove the `ui` section and use an auto-redirect feature.

## Authentication Methods

### Basic Authentication

The following command demonstrates basic authentication process.
The plugin returns JWT token via `Set-Cookie: access_token` and
`token` field in JSON response.

```bash
curl --insecure -H "Accept: application/json" --user webadmin:password123 -v https://127.0.0.1:3443/auth
```

The expected output is as follows:

```
* About to connect() to 127.0.0.1 port 3443 (#0)
*   Trying 127.0.0.1...
* Connected to 127.0.0.1 (127.0.0.1) port 3443 (#0)
* Initializing NSS with certpath: sql:/etc/pki/nssdb
* skipping SSL peer certificate verification
* SSL connection using TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
* Server certificate:
*       subject: E=admin@caddy.local,OU=Local Developement,CN=*.caddy.localhost,L=Local Developement,O=Local Developement,ST=NY,C=US
*       start date: Mar 02 08:01:16 2020 GMT
*       expire date: Feb 28 08:01:16 2030 GMT
*       common name: *.caddy.localhost
*       issuer: E=admin@caddy.local,OU=Local Developement,CN=*.caddy.localhost,L=Local Developement,O=Local Developement,ST=NY,C=US
* Server auth using Basic with user 'webadmin'
> GET /auth HTTP/1.1
> Authorization: Basic d2ViYWRtaW46cGFzc3dvcmQxMjM=
> User-Agent: curl/7.29.0
> Host: 127.0.0.1:3443
> Accept: application/json
>
< HTTP/1.1 200 OK
< Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE3MzE0NzksInN1YiI6IndlYmFkbWluIiwiZW1haWwiOiJ3ZWJhZG1pbkBsb2NhbGRvbWFpbi5sb2NhbCIsInJvbGVzIjpbInN1cGVyYWRtaW4iLCJndWVzdCIsImFub255bW91cyJdLCJvcmlnaW4iOiJsb2NhbGhvc3QifQ.OmFOCu-UJdx16FYLa2ezr7WRmOdUbgrQadhfk1tN4AliIwu69x9TLgzoke_Cr3TqzvMjlQDd22r-3DHBXuzllw
< Cache-Control: no-store
< Content-Type: application/json
< Pragma: no-cache
< Server: Caddy
< Set-Cookie: access_token=eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE3MzE0NzksInN1YiI6IndlYmFkbWluIiwiZW1haWwiOiJ3ZWJhZG1pbkBsb2NhbGRvbWFpbi5sb2NhbCIsInJvbGVzIjpbInN1cGVyYWRtaW4iLCJndWVzdCIsImFub255bW91cyJdLCJvcmlnaW4iOiJsb2NhbGhvc3QifQ.OmFOCu-UJdx16FYLa2ezr7WRmOdUbgrQadhfk1tN4AliIwu69x9TLgzoke_Cr3TqzvMjlQDd22r-3DHBXuzllw Secure; HttpOnly;
< Date: Tue, 09 Jun 2020 19:22:59 GMT
< Content-Length: 318
<
* Connection #0 to host 127.0.0.1 left intact
{"token":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE3MzE0NzksInN1YiI6IndlYmFkbWluIiwiZW1haWwiOiJ3ZWJhZG1pbkBsb2NhbGRvbWFpbi5sb2NhbCIsInJvbGVzIjpbInN1cGVyYWRtaW4iLCJndWVzdCIsImFub255bW91cyJdLCJvcmlnaW4iOiJsb2NhbGhvc3QifQ.OmFOCu-UJdx16FYLa2ezr7WRmOdUbgrQadhfk1tN4AliIwu69x9TLgzoke_Cr3TqzvMjlQDd22r-3DHBXuzllw"}
```

### Form-Based Authentication

TBD.

## User Interface Features

### Auto-Redirect URL

Consider the following configuration snippet. When the JWT plugin detects
unauthenticated user, it forwards the user to `https://auth.example.com`.
The `redirect_url` in URL query creates `AUTH_PORTAL_REDIRECT_URL` cookie
in the users session. Upon successful authentication, the portal
clears the cookie and redirects the user to the path specified in
`AUTH_PORTAL_REDIRECT_URL` cookie.

```
https://chat.example.com {
  jwt {
    auth_url https://auth.example.com/auth?redirect_url=https://chat.example.com
  }
}
```

### User Registration

The following Caddy configuration enables user registration.

```
registration {
  dropbox /etc/gatekeeper/auth/local/registrations/
  title "User Registration"
  code "NY2020"
  require accept_terms
}
```

The parameters are:

* `dropbox`: The directory path to drop registration files
* `code`: The registration code. A user must know what that code is to
  successfully submit a registration request.
* `require accept_terms`: A user must accept terms and conditions, as well
  as privacy policy to proceed
* `disabled on`: disables user registration
* `title`: changes the title of the registration page

This screenshot is the registration screen with default options:

TODO: add caddy_auth_portal_registration_simple.png

The following is the registration screen with mandatory registration
code and the acceptable of terms and conditions:

TODO: add caddy_auth_portal_registration_terms_code.png

## Local Authentication Backend

### Configuration Primer

Please refer to the `assets/conf/local/config.json` configuration file when
configurin the plugin backend. In the example, the route refers to `local` backend in
the file `assets/backends/local/users.json`. Specify the path to the file
where you want your database to reside. Do not create a file, but rather
create leading directories.

For example, create `/etc/caddy/auth/local` directory and specify the
`path` value as:

```json
"path": "/etc/caddy/auth/local/users.json",
```

Next, start the server, and find the following following log entries:

```json
{"level":"info","ts":1588704471.5784082,"logger":"http.authentication.providers.portal","msg":"created new user","user_id":"cd5f647a-cc04-4ae2-9d0a-2d5e9b95cf98","user_name":"webadmin","user_email":"webadmin@localdomain.local","user_claims":{"roles":"superadmin"}}
{"level":"info","ts":1588704471.5784378,"logger":"http.authentication.providers.portal","msg":"created default superadmin user for the database","user_name":"webadmin","user_secret":"d87e7749-0dd8-482b-91a2-ada370263293"}
```

### Identity Store

The `user_name` and `user_secret` are password for the `superuser` in the database.

The plugin creates the following a file having the following structure.

```json
{
  "revision": 1,
  "users": [
    {
      "id": "cd5f647a-cc04-4ae2-9d0a-2d5e9b95cf98",
      "username": "webadmin",
      "email_addresses": [
        {
          "address": "webadmin@localdomain.local",
          "domain": "localdomain.local"
        }
      ],
      "passwords": [
        {
          "purpose": "generic",
          "type": "bcrypt",
          "hash": "$2a$10$B67nHY0PEdxLYdyoLk1YLOomvs.T/dSIyzPuoX9vWULrsD3PRf/sq",
          "cost": 10,
          "expired_at": "0001-01-01T00:00:00Z",
          "created_at": "2020-05-05T18:47:51.513552501Z",
          "disabled_at": "0001-01-01T00:00:00Z"
        }
      ],
      "created": "2020-05-05T18:47:51.513552066Z",
      "last_modified": "2020-05-05T18:47:51.513552175Z",
      "roles": [
        {
          "name": "superadmin"
        }
      ]
    }
  ]
}
```

Finally, browse to `/auth` and login with the username and password:

<img src="https://raw.githubusercontent.com/greenpau/caddy-auth-ui/main/assets/docs/_static/images/forms_login.png">

### Password Management

An administrator may change the password directly in
`/etc/caddy/auth/local/users.json` file.

First, download `bcrypt-cli`:

```bash
go get -u github.com/bitnami/bcrypt-cli
```

Then, use it to generate a new password:

```bash
$ echo -n "password123" | bcrypt-cli -c 10
$2a$10$OVnOaHDkcOXfbUZPFh5qt.yJqUt6pl9uJaqEMxxM.vS5fY/cZNmsq
```

Finally, replace the newly generated password is user database file.

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
