# caddy-auth-forms

<a href="https://github.com/greenpau/caddy-auth-forms/actions/" target="_blank"><img src="https://github.com/greenpau/caddy-auth-forms/workflows/build/badge.svg?branch=master"></a>
<a href="https://pkg.go.dev/github.com/greenpau/caddy-auth-forms" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
<a href="https://caddy.community" target="_blank"><img src="https://img.shields.io/badge/community-forum-ff69b4.svg"></a>

Form-Based Authentication Plugin for for [Caddy v2](https://github.com/caddyserver/caddy).

## Getting Started

Please create the following
[route](https://github.com/greenpau/caddy-auth-forms/blob/a9b8b2421c5ece99dc30c09aa9224049f1aa146c/assets/conf/Caddyfile.json#L19-L69)
in your configuration. In the example, the route refers to `local` backend in
the file `assets/backends/local/users.json`. Specify the path to the file
where you want your database to reside. Do not create a file, but rather
create leading directories.

For example, create `/etc/caddy/auth/local` directory and specify the
`path` value as:

```json
"path": "/etc/caddy/auth/local/users.json",
```

Next, start the server, and find the following following log entries:

```json
{"level":"info","ts":1588704471.5784082,"logger":"http.authentication.providers.forms","msg":"created new user","user_id":"cd5f647a-cc04-4ae2-9d0a-2d5e9b95cf98","user_name":"webadmin","user_email":"webadmin@localdomain.local","user_claims":{"roles":"superadmin"}}
{"level":"info","ts":1588704471.5784378,"logger":"http.authentication.providers.forms","msg":"created default superadmin user for the database","user_name":"webadmin","user_secret":"d87e7749-0dd8-482b-91a2-ada370263293"}
```

The `user_name` and `user_secret` are password for the `superuser` in the database.

The plugin creates the following a file having the following structure.

```json
{
  "revision": 1,
  "users": [
    {
      "id": "cd5f647a-cc04-4ae2-9d0a-2d5e9b95cf98",
      "username": "webadmin",
      "email_addresses": [
        {
          "address": "webadmin@localdomain.local",
          "domain": "localdomain.local"
        }
      ],
      "passwords": [
        {
          "purpose": "generic",
          "type": "bcrypt",
          "hash": "$2a$10$B67nHY0PEdxLYdyoLk1YLOomvs.T/dSIyzPuoX9vWULrsD3PRf/sq",
          "cost": 10,
          "expired_at": "0001-01-01T00:00:00Z",
          "created_at": "2020-05-05T18:47:51.513552501Z",
          "disabled_at": "0001-01-01T00:00:00Z"
        }
      ],
      "created": "2020-05-05T18:47:51.513552066Z",
      "last_modified": "2020-05-05T18:47:51.513552175Z",
      "roles": [
        {
          "name": "superadmin"
        }
      ]
    }
  ]
}
```

Finally, browse to `/auth` and login with the username and password:

<img src="https://raw.githubusercontent.com/greenpau/caddy-auth-ui/master/assets/docs/_static/images/forms_login.png">
