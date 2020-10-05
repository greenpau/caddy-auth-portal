
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
    auth_portal {
      path /auth
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

### OAuth 2.0 Authorization Servers and Identity Providers

The Caddyfile snippet for generic (non-specific) OAuth 2.0 backend.

Based on the below configuration, OAuth 2.0 endpoint is `/auth/oauth2/generic`. If a user
browses to the endpoint, the user will be redirected to the provider discovered via
`metadata_url` and `base_auth_url` URLs.

```
127.0.0.1, localhost {
  route /auth* {
    auth_portal {
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
      auth_url /auth/oauth2/generic
    }
    respond * "generic oauth2 sso" 200
  }
```

#### Okta

Create an "Application," by browsing to "Applications" and clicking
"Add Application" button.

For a website, the choice is "Web".

![Okta Developer - New App Choice](./assets/docs/images/oauth2_okta_new_app_choice.png)

Provided your application is running on localhost port 8443, provide the following
information:

Base URI entries:
* `https://myapp.localdomain.local:8443/`
* `https://localhost:8443/`

Login redirect URIs:
* `https://myapp.localdomain.local:8443/auth/oauth2/okta/authorization-code-callback`
* `https://localhost:8443/auth/oauth2/okta/authorization-code-callback`

Logout redirect URIs:
* `https://myapp.localdomain.local:8443/auth/logout`
* `https://localhost:8443/auth/logout`

Group Assignments:
* Everyone
* Viewer
* Editor
* Administrator

Grant type allowed:
* Client acting on behalf of itself
  - Client Credentials: No
* Client acting on behalf of a user
  - Authorization Code: Yes
  - Refresh Token: No
  - Implicit (Hybrid): No


![Okta Developer - New App Setup](./assets/docs/images/oauth2_okta_new_app.png)

Review the newly created application.

![Okta Developer - Settings - General](./assets/docs/images/oauth2_okta_app_settings_01.png)

Store the credentials securely.

![Okta Developer - Settings - Client Credentials](./assets/docs/images/oauth2_okta_app_settings_02.png)

Review default Sign On Policy.

![Okta Developer - Settings - Sign On](./assets/docs/images/oauth2_okta_app_settings_03.png)

By default, the default Authorization Server has no `groups` scope.

Therefore, browse to "API", "Authorization Servers" and select "default".

![Okta Developer - API](./assets/docs/images/okta_configure_scope_01.png)

![Okta Developer - API](./assets/docs/images/okta_configure_scope_02.png)

Next, browse to "Scopes" and click "Add Scope".

Fill out the "Add Scope" form:
* Name: `groups`
* Description: `This allows the app to view your group memberships.`
* Check "Set as a default scope"
* Check "Include in public metadata"

![Okta Developer - Add Scope](./assets/docs/images/okta_configure_scope_03.png)

Next, browse to "Claims" and click "Add Claim".

Fill out the "Add Claim" form:
* Name: `groups`
* Include in token type: "ID Token", "Always"
* Value type: Groups
* Filter: Matches `.*` regex
* Include in: The "groups" scope

![Okta Developer - Add Scope](./assets/docs/images/okta_configure_scope_04.png)

Next, review [Okta OpenID Connect and OAuth 2.0 API - Get Started](https://developer.okta.com/docs/reference/api/oidc/#get-started).

The Caddyfile snipper for Okta OAuth 2.0 backend is as follows.

Based on the below configuration, Okta endpoint is `/auth/oauth2/okta`. If a user
browses to the endpoint, the user will be redirected to Okta.

```
127.0.0.1, localhost {
  route /auth* {
    auth_portal {
      backends {
        okta_oauth2_backend {
          method oauth2
          realm okta
          provider okta
          domain dev-680653.okta.com
          client_id 0oa121qw81PJW0Tj34x7
          client_secret b3aJC5E59hU18YKC7Yca3994F4qFhWiAo_ZojanF
          server_id default
          scopes openid email profile groups
        }
```

Next, protect a route, e.g. `/sso/oauth2/okta*`. When a user accesses the page, the
the user will be redirected to `/auth/oauth2/okta` and, then, to Okta. Once authenticated,
the user will be redirected back to `/sso/oauth2/okta...`, i.e. back to the path the user
came from.

```
  route /sso/oauth2/okta* {
    jwt {
      auth_url /auth/oauth2/okta
    }
    respond * "okta oauth2 sso" 200
  }
```

Provided the Okta domain is `dev-680653.okta.com`, the authorization server is
`default`, and Client ID is `0oa121qw81PJW0Tj34x7`, check OpenID configuration:

```bash
curl -X GET "https://dev-680653.okta.com/oauth2/default/.well-known/openid-configuration?client_id=0oa121qw81PJW0Tj34x7" | jq
```

By default, the plugin logs public keys from `keys` endpoint.

[:arrow_up: Back to Top](#table-of-contents)

#### Google Identity Platform

References:
* [Google Identity Platform - Using OAuth 2.0 for Web Server Applications](https://developers.google.com/identity/protocols/oauth2/web-server#httprest_2)
* [Google Identity Platform - Identity Platform - OpenID Connect](https://developers.google.com/identity/protocols/oauth2/openid-connect)

The Caddyfile snippet for Google OAuth 2.0 OpenID backend is as follows.

Based on the below configuration, Google endpoint is `/auth/oauth2/google`. If a user
browses to the endpoint, the user will be redirected to Google.

```
127.0.0.1, localhost {
  route /auth* {
    auth_portal {
      backends {
        google_oauth2_backend {
          method oauth2
          realm google
          provider google
          client_id XXXXXXXXXXXXXXXXX.apps.googleusercontent.com
          client_secret YYYYYYYYYYYYYYYYYY
          scopes openid email profile
        }
```

Next, protect a route, e.g. `/sso/oauth2/google*`. When a user accesses the page, the
the user will be redirected to `/auth/oauth2/google` and, then, to Google. Once authenticated,
the user will be redirected back to `/sso/oauth2/google...`, i.e. back to the path the user
came from.

```
  route /sso/oauth2/google* {
    jwt {
      auth_url /auth/oauth2/google
    }
    respond * "google oauth2 sso" 200
  }
```

First, create new application, e.g. "My Gatekeeper".

![Google Identity Platform - Identity Platform - New Application](./assets/docs/images/oauth2_google_new_app.png)

After the creation of the app, you will land on Credentials page.

![Google Identity Platform - Identity Platform - Credentials](./assets/docs/images/oauth2_google_credentials.png)

Click "Configure Consent Screen" and select an appropriate option, e.g. "External".

![Google Identity Platform - Identity Platform - Consent Screen](./assets/docs/images/oauth2_google_consent_screen.png)

Next, provide the name for the application, e.g. "My Gatekeeper" and select appropriate support email.

![Google Identity Platform - Identity Platform - Consent Screen Configuration](./assets/docs/images/oauth2_google_consent_screen_config.png)

After configuring the consent screen you will see the following.

![Google Identity Platform - Identity Platform - Consent Screen Verification](./assets/docs/images/oauth2_google_consent_screen_verification.png)

Next, browse to "Credentials" and click "Create Credentials". Then, choose "OAuth client ID":

![Google Identity Platform - Identity Platform - New Credentials](./assets/docs/images/oauth2_google_new_credentials.png)

First, choose the type of credentials:

![Google Identity Platform - Identity Platform - Consent Screen](./assets/docs/images/oauth2_google_new_credentials_type_choice.png)

Next, provide Redirect URL:

![Google Identity Platform - Identity Platform - Consent Screen](./assets/docs/images/oauth2_google_new_credentials_uri_choice.png)

Login redirect URIs:
* `https://localhost:8443/auth/oauth2/google/authorization-code-callback`

Finally, you will get a confirmation. Store the Client ID and Client Secret securely.

![Google Identity Platform - Identity Platform - Consent Screen](./assets/docs/images/oauth2_google_new_credentials_confirm.png)

[:arrow_up: Back to Top](#table-of-contents)

#### Auth0

TBD.

[:arrow_up: Back to Top](#table-of-contents)

#### OneLogin

TBD.

[:arrow_up: Back to Top](#table-of-contents)


#### Microsoft

TBD.

[:arrow_up: Back to Top](#table-of-contents)

#### Github

Follow the instructions at `https://github.com/settings/apps/new`.

GitHub App name: "My Gatekeeper"

Description: "Caddy v2 Authentication Portal"

Homepage URL: `https://localhost:8443/`

User authorization callback URL: `https://localhost:8443/auth/oauth2/github/authorization-code-callback`

Check "Expire user authorization tokens".

Check "Request user authorization (OAuth) during installation"

Upon successful completion of the instructions, you will get:

![Settings - Developer settings - GitHub Apps - My Gatekeeper](./assets/docs/images/oauth2_github_new_app.png)

Additionally, click "generate a private key" to sign access token requests.

![Settings - Developer settings - GitHub Apps - My Gatekeeper - Private Keys](./assets/docs/images/oauth2_github_sign_keys.png)


Caddyfile configuration:

```
        github_oauth2_backend {
          method oauth2
          realm github
          provider github
          client_id CLIENT_ID
          client_secret CLIENT_SECRET
          scopes user
        }
```

The `github` provider does not have mail claim, i.e. email address. Therefore,
if there is a need to assign a role to a user, one could user `user` directive
to match on `sub`, i.e. subject claim. The `sub` claim is in the format of
`github.com/<GITHUB_HANDLE>`.

```
        github_oauth2_backend {
          ...
          user github.com/greenpau add role superuser
        }
```

The users authenticating via Github would have to accept the terms:

![Settings - Developer settings - GitHub Apps - My Gatekeeper - Accept Terms Screen](./assets/docs/images/oauth2_github_accept_screen.png)

[:arrow_up: Back to Top](#table-of-contents)

<!--- end of section -->
