
## User Transforms

A user transform allows to perform the following one a user passed
authentication:

* add/remove user roles
* add link to UI portal page
* require multi-factor authentication (MFA/2FA)
* require accepting term and conditions

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
    exact match email webadmin@localdomain.local
    action require mfa
  }
}
```

[:arrow_up: Back to Top](#table-of-contents)

<!--- end of section -->
