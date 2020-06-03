# caddy-auth-forms

<a href="https://github.com/greenpau/caddy-auth-forms/actions/" target="_blank"><img src="https://github.com/greenpau/caddy-auth-forms/workflows/build/badge.svg?branch=master"></a>
<a href="https://pkg.go.dev/github.com/greenpau/caddy-auth-forms" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
<a href="https://caddy.community" target="_blank"><img src="https://img.shields.io/badge/community-forum-ff69b4.svg"></a>

Authentication Plugin for [Caddy v2](https://github.com/caddyserver/caddy)
implementing Form-Based Authentication and Basic Authentication.

Please ask questions either here or via LinkedIn. I am happy to help you! @greenpau

## Overview

The purpose of this plugin is providing **authentication** only. The plugin
issue JWT tokens upon successful authentication. In turn, the **authorization**
of the tokens is being handled by [`caddy-auth-jwt`](https://github.com/greenpau/caddy-auth-jwt).

The plugin supports the following **authentication** backends:

* Local (`local`) - JSON flat file database
* LDAP (`ldap`) - remote Microsoft AD database

Please follow these links for the documentation:

* [Local]('./pkg/backends/local/README.md')
* [LDAP]('./pkg/backends/ldap/README.md')

The plugin accepts user credentials for **authentication** with:

* Form-based Authentication: `POST` with `application/x-www-form-urlencoded`
* Basic Authentication: `GET` with `Authorization: Basic` header
