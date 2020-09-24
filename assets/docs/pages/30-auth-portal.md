
## Authentication Portal

<table cellspacing="0" cellpadding="0" style="border-collapse: collapse; border: none; vertical-align: top;">
  <tr style="border: none;">
    <td style="border: none; vertical-align: top;">
      <img src="https://raw.githubusercontent.com/greenpau/caddy-auth-portal/main/assets/docs/images/forms_login.png">
    </td>
    <td style="border: none; vertical-align: top;">
      <img src="https://raw.githubusercontent.com/greenpau/caddy-auth-portal/main/assets/docs/images/forms_portal.png">
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

TODO: Review [Refactoring UI Feed](https://twitter.com/i/events/994601867987619840)
and [Refactoring UI Website](https://refactoringui.com/).

[:arrow_up: Back to Top](#table-of-contents)

<!--- end of section -->