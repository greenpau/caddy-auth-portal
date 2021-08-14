## OAuth 2.0 and OpenID Connect (OIDC) Authentication Backend

### OAuth 2.0 Flow

Generally, a developer must create an "Application" with and identity provider.
e.g. Google, Okta, Azure, etc., and obtain OAuth 2.0 "Client ID" and
"Client Secret".

The authentication flow begins with obtaining "Authorization Code" from an
identity provider.

* What does the portal send to Okta?
  - Client ID
  - Redirect URI
  - Response Type
  - Scope

* What does the portal receive from Okta?
  - Authorization Code

Once, the portal has the "Authorization Code", it could get "Access Token"
to access the user's data at the identity provider.

* What does the portal send to Okta?
  - Authorization Code
  - Client ID
  - Client Secret

* What does Okta respond with?
  - Access Token

* What could the portal use "Access Token" for?
  -  Make API calls to obtain user information

The OpenID Connect (OIDC) adds login and profile information about the person
who is logged in. The differences between standard OAuth2.0 flow are:

1. In the initial request, a specific scope of `openid` is used
2. In the final exchange the Client receives both an "Access Token" and an "ID Token" (JWT Token).

References:
* [Mozilla - OIDC in a nutshell](https://infosec.mozilla.org/guidelines/iam/openid_connect.html#oidc-in-a-nutshell)

[:arrow_up: Back to Top](#table-of-contents)

### Adding Role Claims

The Caddyfile `user` directive allows adding roles to
a user based on the user's email.

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

In sum, Caddyfile may look as follows:

```
myapp.localdomain.local, localhost, 127.0.0.1 {
  route /auth* {
    authp {
      backends {
        google_oauth2_backend {
          method oauth2
          realm google
          provider google
          client_id XXXXXXXXXXXXXX.apps.googleusercontent.com
          client_secret YYYYYYYYYYYYYYYYY
          scopes openid email profile
          user "^greenpau" regex add role superuser
        }
```
