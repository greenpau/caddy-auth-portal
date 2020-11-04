
## User Interface Features

### Auto-Redirect URL

Consider the following configuration snippet. When the JWT plugin detects
unauthenticated user, it forwards the user to `https://auth.example.com`.
The `redirect_url` in URL query creates `AUTH_PORTAL_REDIRECT_URL` cookie
in the users session. Upon successful authentication, the portal
clears the cookie and redirects the user to the path specified in
`AUTH_PORTAL_REDIRECT_URL` cookie.

```
https://chat.example.com {
  jwt {
    auth_url https://auth.example.com/auth?redirect_url=https://chat.example.com
  }
}
```

### User Registration

The following Caddy configuration enables user registration.

```
registration {
  dropbox /etc/gatekeeper/auth/local/registrations_db.json
  title "User Registration"
  code "NY2020"
  require accept_terms
  require domain_mx
}
```

The parameters are:

* `dropbox`: The file path pointing to registration database.
* `code`: The registration code. A user must know what that code is to
  successfully submit a registration request.
* `require accept_terms`: A user must accept terms and conditions, as well
  as privacy policy to proceed
* `disabled on`: disables user registration
* `title`: changes the title of the registration page
* `require domain_mx`: forces the check of domain MX record

This screenshot is the registration screen with default options:

<img src="https://raw.githubusercontent.com/greenpau/caddy-auth-portal/main/assets/docs/images/portal_registration_simple.png">

The following is the registration screen with mandatory registration
code and the acceptable of terms and conditions:

<img src="https://raw.githubusercontent.com/greenpau/caddy-auth-portal/main/assets/docs/images/portal_registration_terms_code.png">

[:arrow_up: Back to Top](#table-of-contents)

### Custom CSS Styles

The following Caddyfile directive adds a custom CSS stylesheet to the
plugin's pages:

```
      ui {
        ...
        custom_css_path path/to/styles.css
        ...
      }
```

[:arrow_up: Back to Top](#table-of-contents)

<!--- end of section -->
