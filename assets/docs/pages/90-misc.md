
## Miscellaneous

### Binding to Privileged Ports

It may be necessary to bind Caddy to privileged port, e.g. 80 or 443.
Grant the `cap_net_bind_service` capability to the Caddy binary, e.g.:

```bash
sudo systemctl stop gatekeeper
sudo rm -rf /usr/local/bin/gatekeeper
sudo cp bin/caddy /usr/local/bin/gatekeeper
sudo setcap cap_net_bind_service=+ep /usr/local/bin/gatekeeper
sudo systemctl start gatekeeper
```

[:arrow_up: Back to Top](#table-of-contents)

### Recording Source IP Address in JWT Token

The `enable source ip tracking` Caddyfile directive instructs
the plugin to record the source IP address when issuing claims.

```
localhost {
  route /auth* {
    auth_portal {
      ...
      enable source ip tracking
      ...
```

This could be useful to force re-authentication when the client IP
address changes.

### Session ID Cache

When the plugin issues JWT tokens, it either passes `jti` values
from upstream providers or generates its own `jti` values.

The plugin stores the mappings between `jti` value and associated
data in a cache. The associated data contains claims and the
metadata from the backend which authenticated a particular session.

This cache is used to assess whether a claim holder is able using
certain portal's capabilities, e.g. add public SSH/GPG key, configure
MFA tokens, change password, etc.

[:arrow_up: Back to Top](#table-of-contents)

### Caddyfile Shortcuts

The following snippet with either `jwt_token_file` or `jwt_token_rsa_file`
Caddyfile directive:

```
    auth_portal {
      jwt_token_file 1 /etc/caddy/auth/jwt/jwt_privatekey.pem
      jwt_token_rsa_file 2 /etc/caddy/auth/jwt/jwt_privatekey.pem
      ...
    }
```

Replaces:

```
    auth_portal {
      jwt {
        token_rsa_file 1 /etc/caddy/auth/jwt/jwt_privatekey.pem
      }
      ...
    }
```

The following snippet with `jwt_token_name` Caddyfile directive:

```
    auth_portal {
      jwt_token_name access_token
      ...
    }
```

Replaces:

```
    auth_portal {
      jwt {
        token_name access_token
      }
      ...
    }
```

The following snippet with `jwt_token_secret` Caddyfile directive:

```
    auth_portal {
      jwt_token_secret bcc8fd6e-8e45-493e-a146-f178ac676841
      ...
    }
```

Replaces:

```
    auth_portal {
      jwt {
        token_secret bcc8fd6e-8e45-493e-a146-f178ac676841
      }
      ...
    }
```

The following snippet with `jwt_token_lifetime` Caddyfile directive:

```
    auth_portal {
      jwt_token_lifetime 3600
      ...
    }
```

Replaces:

```
    auth_portal {
      jwt {
        token_lifetime 3600
      }
      ...
    }
```

### Adding Role Claims globally

The Caddyfile `rolemapping` { `user` } directive allows adding roles to
a user based on the user's email.

These mappings apply to all authentication backends in an auth_portal, and match on the `email`
claim.

A user with email claim of `contoso.com` would get an additional `superuser` role.

```
          user jsmith@contoso.com add role superuser
```

A user with the email address beginning with `jsmith` would get additional roles.
Specifically, it would be viewer, editor, and admin.

```
          user "^greenpau" regex add roles viewer editor admin
```

All users with `contoso.com` email address would get "employee" role:

```
          user "@contoso.com$" regex add role employee

```

The user role mapping can also be managed using a json file specified using the 
`path` directive, using the following format:

```
[
  { email: "jsmith@contoso.com", match: "exact", roles: ["superuser"] },
  { email: "^greenpau", match: "regex", roles: ["viewer", "editor", "admin"] },
  { email: "@contoso.com$", match: "regex", roles: ["employee"] },
]
```

For example, your Caddyfile may be as follows:

```
myapp.localdomain.local, localhost, 127.0.0.1 {
  route /auth* {
    auth_portal {
      path /auth
      rolemapping {
        user "^greenpau" regex add role superuser
        user jsmith@contoso.com add role superuser
        path /config/caddy/rolemapping/map.json
      }
```
