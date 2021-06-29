
## User Transforms

A user transform allows to perform the following one a user passed
authentication:

* add/remove user roles
* add link to UI portal page
* require multi-factor authentication (MFA/2FA)
* require accepting term and conditions
* block/deny issuing a token

The following transform matches `sub` field and grants `authp/viewer` role:

```
authp {
  transform user {
    exact match sub github.com/greenpau
    action add role authp/viewer
  }
}
```

The following transform, in addition to the above adds a link to a user's
portal page:

```
authp {
  transform user {
    exact match sub github.com/greenpau
    action add role authp/viewer
    ui link "Caddy Version" /version icon "las la-code-branch"
  }
}
```

The following transform requires to pass multi-factor authentication when the
authenticated user's email is `webadmin@localdomain.local`:

```
authp {
  transform user {
    match email webadmin@localdomain.local
    require mfa
  }
}
```

The following transform adds role `verified` to Facebook-authenticated user
with id of `123456789`:

```
authp {
  transform user {
    exact match sub 123456789
    exact match origin facebook
    action add role verified
  }
}
```

The following transform blocks a user with email `anonymous@badactor.com`
from getting authenticated:

```
authp {
  transform user {
    match email anonymous@badactor.com
    block
  }
}
```

The following transform adds role `contoso_users` to the users with emai
address from contoso.com domain:

```
authp {
  transform user {
    suffix match email @contoso.com
    add role contoso_users
  }
}
```

[:arrow_up: Back to Top](#table-of-contents)

<!--- end of section -->
