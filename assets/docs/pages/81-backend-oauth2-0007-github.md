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
