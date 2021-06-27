
## Authorization Cookie

### Intra-Domain Cookies

The following `Caddyfile` settings define the scope of the cookies issued by
the plugin. Specifically, what URLs the cookies should be sent to.
See [MDN - Using HTTP cookies - Define where cookies are sent](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
for more information.

* `cookie domain <domain>`: adds the **Domain** attribute to a cookie. It
  determines which hosts are allowed to receive the cookie. By default,
  the domain is not included.
* `cookie path <path>` (optional): adds the **Path** attribute to a cookie.
  It determines the URL path that must exist in the requested URL in order
  to send  the Cookie header. The default is `/`.
* `cookie lifetime` (optional): sets the number of seconds until the cookie
  expires. The directive sets "Max-Age" cookie attribute.
* `cookie samesite <lax|strict|none>`: specifies SameSite strategy.
* `cookie insecure <on|off>`: Allows sending cookies over HTTP. By default,
  it is disabled.

### JWT Tokens

The plugin issues JWT tokens to authenticated users. The tokens
contains user attributes, e.g. name, email, avatar, etc. They also
contains roles. The roles are used to authorize user access with
`jwt` plugin.

By default, in addition to the roles configured by an authentication provider,
the plugin issues one of the three roles to a user.

* `authp/admin`: this is the admin user. It must be granted by authentication
  provider or added to a user via `transform user` directive
* `authp/user`: the user can access `/settings` endpoint. It must be granted
  by authentication provider or added to a user via `transform user` directive
* `authp/guest`: can access portal only. This is the default role assigned by
  the portal to a user when neither `authp/admin` nor `authp/user` are being
  assigned

The plugin supports the issuance and verification of RSA, ECDSA, and shared keys.
See docs [here](https://github.com/greenpau/caddy-auth-jwt#token-verification).

#### Auto-Generated Encryption Keys

By default, if there is no `crypto key` directive, the plugin auto-generated
ECDSA key pair for signing and verification of tokens. The key pair changes
with each restart of the plugin.

In this case, there is no need to define `crypto key` directive in `jwt` plugin
because the two plugins would know about the keypair.

This is a perfect option for standalone servers.

#### Encryption Key Configuration

##### Shared Key

The following configuration instructs the plugin to sign/verify token
with shared key `428f41ab-67ec-47d1-8633-bcade9dcc7ed` and add key id of
`a2f19072b6d6` to the token's header. It uses the default token lifetime
of 900 seconds (15 minutes). The name of the token is `access_token`.

```
authp {
  crypto key a2f19072b6d6 sign-verify 428f41ab-67ec-47d1-8633-bcade9dcc7ed
}
```

The corresponding `jwt` plugin config is:

```
jwt {
  crypto key a2f19072b6d6 verify 428f41ab-67ec-47d1-8633-bcade9dcc7ed
}
```

The following configuration instructs the plugin to sign/verify token
with shared key `428f41ab-67ec-47d1-8633-bcade9dcc7ed` and add key id of
`a2f19072b6d6` to the token's header. It uses the default token lifetime
of 1800 seconds (900 minutes). The name of the token is `JWT_TOKEN`.


```
authp {
  crypto default token name JWT_TOKEN
  crypto default token lifetime 1800
  crypto key a2f19072b6d6 sign-verify 428f41ab-67ec-47d1-8633-bcade9dcc7ed
}
```

The corresponding `jwt` plugin config is:

```
jwt {
  crypto key a2f19072b6d6 verify 428f41ab-67ec-47d1-8633-bcade9dcc7ed
}
```

The following configuration instructs the plugin to sign/verify token
with shared key `428f41ab-67ec-47d1-8633-bcade9dcc7ed` and add key id of
`a2f19072b6d6` to the token's header. It uses the default token lifetime
of 1800 seconds (900 minutes). The name of the token is `JWT_TOKEN`.


```
authp {
  crypto key sign-verify 428f41ab-67ec-47d1-8633-bcade9dcc7ed
}
```

The corresponding `jwt` plugin config is:

```
jwt {
  crypto key verify 428f41ab-67ec-47d1-8633-bcade9dcc7ed
}
```

[:arrow_up: Back to Top](#table-of-contents)

<!--- end of section -->
