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
    authp {
      backends {
        okta_oauth2_backend {
          method oauth2
          realm okta
          provider okta
          domain_name dev-680653.okta.com
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
    authorize {
      set auth url /auth/oauth2/okta
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
