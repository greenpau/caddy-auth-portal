#### Facebook

Browse to `https://developers.facebook.com/apps/` and click "Create App".

![Facebook Developers - Apps](./assets/docs/images/oauth2_facebook_apps_screen.png)

When asked about "What do you need your app to do?", choose "Build Connected Experiences".

![Facebook Developers - New App - App Type](./assets/docs/images/oauth2_facebook_apps_type_choice_screen.png)

Next, choose the name for the application:

![Facebook Developers - New App - App Name](./assets/docs/images/oauth2_facebook_apps_name_choice_screen.png)

Once your app (in this case App ID is `38409328409`) is available,
click "Set Up" next to "Facebook Login" product:

![Facebook Developers - App Screen](./assets/docs/images/oauth2_facebook_app_screen.png)

When at Quickstart screen, select "Other".

Next, click "Settings - Advanced" on the left navigation bar and browse to "Security" section.

Set "Require App Secret" to "Yes".
The Client Token is not being used because `client_secret` is being used to calculate `appsecret_proof`.

![Facebook Developers - App Settings - Advanced](./assets/docs/images/oauth2_facebook_app_settings_advanced_screen.png)

Next, click "Settings - Basic" on the left navigation bar and extract "App Secret".
The App Secret is used in `client_secret` Caddyfile directive.

![Facebook Developers - App Settings - Basic](./assets/docs/images/oauth2_facebook_app_settings_basic_screen.png)

Next, click "Settings" under "Facebook Login" on the left navigation bar and browse to "Client OAuth Settings" section:

Set "Valid OAuth Redirect URIs" to:

* `https://localhost:8443/auth/oauth2/facebook/authorization-code-callback`

![Facebook Developers - Facebook Login - Settings](./assets/docs/images/oauth2_facebook_app_login_settings_screen.png)

Additionally, add the URL in "Redirect URI Validator":

* `https://localhost:8443/auth/oauth2/facebook/authorization-code-callback`

The Caddyfile config is as follows:

```
127.0.0.1, localhost {
  route /auth* {
    authp {
      backends {
        facebook_oauth2_backend {
          method oauth2
          realm facebook
          provider facebook
          client_id 38409328409
          client_secret 11899bfcd5745a8ed20235c65638f311
        }
```

When a user get redirected to Facebook Login, the screen looks as follows:

![Facebook Developers - Facebook Login - User Login](./assets/docs/images/oauth2_facebook_user_login_screen.png)

[:arrow_up: Back to Top](#table-of-contents)
