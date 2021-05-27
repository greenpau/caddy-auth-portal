
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
    authp {
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
    authp {
      jwt_token_file 1 /etc/caddy/auth/jwt/jwt_privatekey.pem
      jwt_token_rsa_file 2 /etc/caddy/auth/jwt/jwt_privatekey.pem
      ...
    }
```

Replaces:

```
    authp {
      jwt {
        token_rsa_file 1 /etc/caddy/auth/jwt/jwt_privatekey.pem
      }
      ...
    }
```

The following snippet with `jwt_token_name` Caddyfile directive:

```
    authp {
      jwt_token_name access_token
      ...
    }
```

Replaces:

```
    authp {
      jwt {
        token_name access_token
      }
      ...
    }
```

The following snippet with `jwt_token_secret` Caddyfile directive:

```
    authp {
      jwt_token_secret bcc8fd6e-8e45-493e-a146-f178ac676841
      ...
    }
```

Replaces:

```
    authp {
      jwt {
        token_secret bcc8fd6e-8e45-493e-a146-f178ac676841
      }
      ...
    }
```

The following snippet with `jwt_token_lifetime` Caddyfile directive:

```
    authp {
      jwt_token_lifetime 3600
      ...
    }
```

Replaces:

```
    authp {
      jwt {
        token_lifetime 3600
      }
      ...
    }
```
