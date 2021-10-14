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
    authp {
      backends {
        google_oauth2_backend {
          method oauth2
          realm google
          provider google
          client_id XXX.apps.googleusercontent.com
          client_secret YYY
          scopes openid email profile
        }
```

Alternatively, use [Shortcuts](#shortcuts") to accomplish the same:

```
127.0.0.1, localhost {
  route /auth* {
    authp {
      backend google XXX YYY
```

Next, protect a route, e.g. `/sso/oauth2/google*`. When a user accesses the page, the
the user will be redirected to `/auth/oauth2/google` and, then, to Google. Once authenticated,
the user will be redirected back to `/sso/oauth2/google...`, i.e. back to the path the user
came from.

```
  route /sso/oauth2/google* {
    authorize {
      set auth url /auth/oauth2/google
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
