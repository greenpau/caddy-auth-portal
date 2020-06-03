# LDAP Backend

It is recommended to read the documentation for Local backend, because
it outlines important principles of operation of all backends.

Additionally, the LDAP backend works in conjunction with Local backend.
As you will see later, the two can be used together by introducing a
dropdown in UI interface to choose local versus LDAP domain authentication.

The reference configuration for the backend is `assets/conf/ldap/Caddyfile.json`.

The following Caddy endpoint at `/auth` authentications users
from `contoso.com` domain.

There is a single LDAP server associated with the domain: `ldaps://ldaps.contoso.com`.
The plugin ignores certificate errors when connecting to the servers.

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
and uses the following search filter: `(|(sAMAccountName=%s)(mail=%s))`.

Upon successful authentication, the plugin assign the following rules
to a user, provided the user is a member of a group:

| **JWT Role** | **LDAP Group Membership** |
| --- | --- |
| `admin` | `CN=Admins,OU=Security,OU=Groups,DC=CONTOSO,DC=COM` |
| `editor` | `CN=Editors,OU=Security,OU=Groups,DC=CONTOSO,DC=COM` |
| `viewer` | `CN=Viewers,OU=Security,OU=Groups,DC=CONTOSO,DC=COM` |

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
        "forms": {
          "auth_url_path": "/auth",
          "backends": [
            {
              "type": "local",
              "path": "assets/backends/local/users.json",
              "realm": "local"
            },
            {
              "type": "ldap",
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
              "search_filter": "(|(sAMAccountName=%s)(mail=%s))",
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

TODO: add `/assets/docs/images/login_form_domain_code.png`

The code is:

```html
                <div class="input-field">
                  <input id="realm" name="realm" type="text" class="validate">
                  <label for="realm">Domain</label>
                </div>
```

It results in having free form input box.

TODO: add `/assets/docs/images/login_form_domain_input.png`

A user may input the word `local` for Local backend and the
name of the domain for LDAP backend.

TODO: add table with two images:
`/assets/docs/images/login_form_domain_input_with_local.png` and
`/assets/docs/images/login_form_domain_input_with_domain.png`

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

TODO: add `/assets/docs/images/login_form_dropdown_input.png`
