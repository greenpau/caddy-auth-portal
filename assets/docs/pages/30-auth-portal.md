
## Authentication Portal

<table cellspacing="0" cellpadding="0" style="border-collapse: collapse; border: none; vertical-align: top;">
  <tr style="border: none;">
    <td style="border: none; vertical-align: top;">
      <img src="https://raw.githubusercontent.com/greenpau/caddy-auth-portal/main/assets/docs/images/basic_login.png">
    </td>
    <td style="border: none; vertical-align: top;">
      <img src="https://raw.githubusercontent.com/greenpau/caddy-auth-portal/main/assets/docs/images/basic_portal.png">
    </td>
  </tr>
</table>

### User Identity

The following screenshot is from `/auth/whoami` endpoint:

<img src="https://raw.githubusercontent.com/greenpau/caddy-auth-portal/main/assets/docs/images/whoami.png">

### User Settings

The following screenshot is from `/auth/settings/` endpoint:

<img src="https://raw.githubusercontent.com/greenpau/caddy-auth-portal/main/assets/docs/images/settings.png">

### Multi-Factor Authentication MFA

#### Add MFA Authenticator Application

The following screenshot is from `/auth/settings/mfa/add/app` endpoint:

<img src="https://raw.githubusercontent.com/greenpau/caddy-auth-portal/main/assets/docs/images/settings_mfa_app.png">

The QR Code displayed on the page complies [Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

In your MFA application, e.g. Microsoft Authenticator, follow these steps to
onboard your web account.

<table cellspacing="0" cellpadding="0" style="border-collapse: collapse; border: none; vertical-align: top;">
  <tr style="border: none;">
    <td style="border: none; vertical-align: top;">
      <img src="https://raw.githubusercontent.com/greenpau/caddy-auth-portal/main/assets/docs/images/ms_mfa_app_add_account.png">
    </td>
    <td style="border: none; vertical-align: top;">
      <img src="https://raw.githubusercontent.com/greenpau/caddy-auth-portal/main/assets/docs/images/ms_mfa_app_scan_qrcode.png">
    </td>
    <td style="border: none; vertical-align: top;">
      <img src="https://raw.githubusercontent.com/greenpau/caddy-auth-portal/main/assets/docs/images/ms_mfa_app_new_account.png">
    </td>
  </tr>
</table>

### Theming

The theming of the portal works as follows.

It starts with a concept of `theme`. By default, the portal uses `basic` theme.
There is no need to defind it in Caddyfile.

```
localhost {
  route /auth* {
    auth_portal {
      ui {
        theme basic
      }
```

Each theme must have a set of default pages:

* `generic`
* `login`
* `portal`
* `register`
* `whoami`
* `settings`

The plain text templates are being stored in `assets/templates/<THEME>/<PAGE>.template`.

```
assets/templates/basic/generic.template
assets/templates/basic/login.template
assets/templates/basic/portal.template
assets/templates/basic/register.template
assets/templates/basic/whoami.template
assets/templates/basic/settings.template
```

These templates are the parts of `pkg/ui/pages.go`. They are compiled in the
portal's binary. That is, there is no need to store them on the disk.

Next, if a user wants to use a different template, then it could be passed via
Caddyfile directives. Specifically, use `<PAGE>_template` directive to point
to a file on disk.

```
localhost {
  route /auth* {
    auth_portal {
      ui {
        theme basic
        login_template "/etc/gatekeeper/ui/login.template"
      }
```

TODO: Review [Refactoring UI Feed](https://twitter.com/i/events/994601867987619840)
and [Refactoring UI Website](https://refactoringui.com/).

[:arrow_up: Back to Top](#table-of-contents)

<!--- end of section -->
