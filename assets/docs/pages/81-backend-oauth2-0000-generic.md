### OAuth 2.0 Authorization Servers and Identity Providers

The Caddyfile snippet for generic (non-specific) OAuth 2.0 backend.

Based on the below configuration, OAuth 2.0 endpoint is `/auth/oauth2/generic`. If a user
browses to the endpoint, the user will be redirected to the provider discovered via
`metadata_url` and `base_auth_url` URLs.

```
127.0.0.1, localhost {
  route /auth* {
    authp {
      backends {
        generic_oauth2_backend {
          method oauth2
          realm generic
          provider generic
          client_id XXXXXXXXXXXXXXXXXXX
          client_secret YYYYYYYYYYYYYYYYYYYYYY
          scopes openid email profile
        }
```

Next, protect a route, e.g. `/sso/oauth2/generic*`. When a user accesses the page, the
the user will be redirected to `/auth/oauth2/generic` and, then, to the provider. Once authenticated,
the user will be redirected back to `/sso/oauth2/generic...`, i.e. back to the path the user
came from.

```
  route /sso/oauth2/generic* {
    jwt {
      set auth url /auth/oauth2/generic
    }
    respond * "generic oauth2 sso" 200
  }
```
