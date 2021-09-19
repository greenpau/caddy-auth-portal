#### Gitlab

Whether you are using gitlab.com or hosting your own Gitlab instance
(e.g. at `gitlab.contoso.com`), create a new app by browsing to
one of the following URLs:

* `https://gitlab.contoso.com/-/profile/applications`
* `https://gitlab.com/-/profile/applications`

![Gitlab - New Application](./assets/docs/images/oauth_gitlab_new_app_1.png)

![Gitlab - New Application - Scopes](./assets/docs/images/oauth_gitlab_new_app_2.png)

![Gitlab - New Application - Review](./assets/docs/images/oauth_gitlab_new_app_2.png)

Next, create a configuration for the backend, e.g.:

```
app.contoso.com {
  route /auth* {
    authp {
      backends {
        gitlab_oauth2_backend {
          method oauth2
          realm gitlab
          provider gitlab
          domain_name gitlab.contoso.com
          client_id 522a2f714a1e978c52e80909e543e2a51
          client_secret d562a48c29a686b343978edbc8ac3d3
          scopes openid email profile
          user_group_filters barfoo
          user_group_filters ^a
        }
      }
      ui {
        links {
          "My Website" / icon "las la-star"
          "My Identity" "/auth/whoami" icon "las la-star"
        }
      }
      transform user {
        match origin gitlab
        action add role authp/user
      }
      transform user {
        match origin gitlab
        match email greenpau@contoso.com
        action add role authp/admin
      }
    }
  }

  route {
    jwt {
      primary yes
      allow roles authp/admin authp/user
      validate bearer header
      set auth url /auth/oauth2/gitlab
      inject headers with claims
    }
    respond * "my app" 200
  }
}
```

By default, Gitlab groups are not included into the token, unless
the `user_group_filters` directive is being user in the configuration.

The following directives instruct the portal to add the groups having
`barfoo` in their name and the groups whose names start with the `a`.

```
          user_group_filters barfoo
          user_group_filters ^a
```

In this case, the groups making it to the JWT token are:

```
    "gitlab.contoso.com/barfoo",
    "gitlab.contoso.com/a-private-group/a-subgroup"
```

When a user browses to the app and clicks Gitlab link, the user is being redirected to
Gitlab instance. 

![Gitlab - Initiate Login](./assets/docs/images/oauth_gitlab_init.png)

The user should click Authorize to continue.

![Gitlab - Authorize App](./assets/docs/images/oauth_gitlab_authorize_app_1.png)

Once logged in, the user may browse to "My Identity".

![Gitlab - Portal](./assets/docs/images/oauth_gitlab_portal.png)

The relevant Gitlab data became a part of the JWT token issued by the portal.

![Gitlab - User Identity](./assets/docs/images/oauth_gitlab_user_identity.png)

[:arrow_up: Back to Top](#table-of-contents)
