# caddy-auth-portal

<a href="https://github.com/greenpau/caddy-auth-portal/actions/" target="_blank"><img src="https://github.com/greenpau/caddy-auth-portal/workflows/build/badge.svg?branch=main"></a>
<a href="https://pkg.go.dev/github.com/greenpau/caddy-auth-portal" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
<a href="https://caddy.community" target="_blank"><img src="https://img.shields.io/badge/community-forum-ff69b4.svg"></a>

Authentication Plugin for [Caddy v2](https://github.com/caddyserver/caddy) implementing
Form-Based, Basic, Local, LDAP, OpenID Connect, OAuth 2.0, SAML Authentication.

**Documentation**: [authp.github.io](https://authp.github.io/docs/authenticate/intro)

**Security Policy**: [SECURITY.md](SECURITY.md)

Please show your appreciation for this work and :star: :star: :star:

Please ask questions either here or via LinkedIn. I am happy to help you! @greenpau

Please see other plugins:
* [caddy-authorize](https://github.com/greenpau/caddy-authorize)
* [caddy-trace](https://github.com/greenpau/caddy-trace)
* [caddy-systemd](https://github.com/greenpau/caddy-systemd)

Download Caddy with the plugins enabled:


<!-- begin-markdown-toc -->
## User Interface

* [User Login](#user-login)
* [Portal](#portal)
* [User Identity (whoami)](#user-identity-whoami)
* [User Settings](#user-settings)
  * [Password Management](#password-management)
  * [Add U2F Token (Yubico)](#add-u2f-token-yubico)
  * [Add Authenticator App](#add-authenticator-app)
* [Multi-Factor Authentication](#multi-factor-authentication)

<!-- end-markdown-toc -->

## User Login

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_01.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_02.png)

## Portal

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_03.png)

## User Identity (whoami)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_04.png)

## User Settings

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_05.png)

### Password Management

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_06.png)

### Add U2F Token (Yubico)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_07.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_08.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_09.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_10.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_11.png)

### Add Authenticator App

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_12.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/ms_mfa_app_add_account.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/ms_mfa_app_new_account.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/ms_mfa_app_scan_qrcode.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_13.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_14.png)

## Multi-Factor Authentication

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_15.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_16.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_17.png)

* <a href="https://caddyserver.com/api/download?os=linux&arch=amd64&p=github.com%2Fgreenpau%2Fcaddy-auth-portal%40v1.4.37&p=github.com%2Fgreenpau%2Fcaddy-authorize%40v1.3.24&p=github.com%2Fgreenpau%2Fcaddy-trace%40v1.1.8" target="_blank">linux/amd64</a>
* <a href="https://caddyserver.com/api/download?os=windows&arch=amd64&p=github.com%2Fgreenpau%2Fcaddy-auth-portal%40v1.4.37&p=github.com%2Fgreenpau%2Fcaddy-authorize%40v1.3.24&p=github.com%2Fgreenpau%2Fcaddy-trace%40v1.1.8" target="_blank">windows/amd64</a>
