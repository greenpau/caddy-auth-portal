
## Overview

The purpose of this plugin is providing **authentication** only. The plugin
issue JWT tokens upon successful authentication. In turn, the **authorization**
of the tokens is being handled by [`caddy-auth-jwt`](https://github.com/greenpau/caddy-auth-jwt).

The plugin supports the following **authentication** backends:

* Local (`local`) - JSON flat file database
* LDAP (`ldap`) - remote Microsoft AD database

The plugin accepts user credentials for **authentication** with:

* Form-based Authentication: `POST` with `application/x-www-form-urlencoded`
* Basic Authentication: `GET` with `Authorization: Basic` header

The following digram is visual representation of the configuration of
[`caddy-auth-portal`](https://github.com/greenpau/caddy-auth-portal) and
[`caddy-auth-jwt`](https://github.com/greenpau/caddy-auth-jwt).

![Authentication Plugins](assets/docs/images/auth_plugin_arch.png)

[:arrow_up: Back to Top](#table-of-contents)

<!--- end of section -->