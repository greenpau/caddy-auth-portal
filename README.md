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

* [Local](./pkg/backends/local/README.md)
* [LDAP](./pkg/backends/ldap/README.md)

The plugin accepts user credentials for **authentication** with:

* Form-based Authentication: `POST` with `application/x-www-form-urlencoded`
* Basic Authentication: `GET` with `Authorization: Basic` header

The following digram is visual representation of the configuration of
[`caddy-auth-forms`](https://github.com/greenpau/caddy-auth-forms) and
[`caddy-auth-jwt`](https://github.com/greenpau/caddy-auth-jwt).

![Authentication Plugins](assets/docs/images/auth_plugin_arch.png)

## Authentication Forms

### Basic Authentication

The following command demonstrates basic authentication process.
The plugin returns JWT token via `Set-Cookie: access_token` and
`token` field in JSON response.

```bash
curl --insecure -H "Accept: application/json" --user webadmin:password123 -v https://127.0.0.1:3443/auth
```

The expected output is as follows:

```
* About to connect() to 127.0.0.1 port 3443 (#0)
*   Trying 127.0.0.1...
* Connected to 127.0.0.1 (127.0.0.1) port 3443 (#0)
* Initializing NSS with certpath: sql:/etc/pki/nssdb
* skipping SSL peer certificate verification
* SSL connection using TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
* Server certificate:
*       subject: E=admin@caddy.local,OU=Local Developement,CN=*.caddy.localhost,L=Local Developement,O=Local Developement,ST=NY,C=US
*       start date: Mar 02 08:01:16 2020 GMT
*       expire date: Feb 28 08:01:16 2030 GMT
*       common name: *.caddy.localhost
*       issuer: E=admin@caddy.local,OU=Local Developement,CN=*.caddy.localhost,L=Local Developement,O=Local Developement,ST=NY,C=US
* Server auth using Basic with user 'webadmin'
> GET /auth HTTP/1.1
> Authorization: Basic d2ViYWRtaW46cGFzc3dvcmQxMjM=
> User-Agent: curl/7.29.0
> Host: 127.0.0.1:3443
> Accept: application/json
>
< HTTP/1.1 200 OK
< Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE3MzE0NzksInN1YiI6IndlYmFkbWluIiwiZW1haWwiOiJ3ZWJhZG1pbkBsb2NhbGRvbWFpbi5sb2NhbCIsInJvbGVzIjpbInN1cGVyYWRtaW4iLCJndWVzdCIsImFub255bW91cyJdLCJvcmlnaW4iOiJsb2NhbGhvc3QifQ.OmFOCu-UJdx16FYLa2ezr7WRmOdUbgrQadhfk1tN4AliIwu69x9TLgzoke_Cr3TqzvMjlQDd22r-3DHBXuzllw
< Cache-Control: no-store
< Content-Type: application/json
< Pragma: no-cache
< Server: Caddy
< Set-Cookie: access_token=eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE3MzE0NzksInN1YiI6IndlYmFkbWluIiwiZW1haWwiOiJ3ZWJhZG1pbkBsb2NhbGRvbWFpbi5sb2NhbCIsInJvbGVzIjpbInN1cGVyYWRtaW4iLCJndWVzdCIsImFub255bW91cyJdLCJvcmlnaW4iOiJsb2NhbGhvc3QifQ.OmFOCu-UJdx16FYLa2ezr7WRmOdUbgrQadhfk1tN4AliIwu69x9TLgzoke_Cr3TqzvMjlQDd22r-3DHBXuzllw Secure; HttpOnly;
< Date: Tue, 09 Jun 2020 19:22:59 GMT
< Content-Length: 318
<
* Connection #0 to host 127.0.0.1 left intact
{"token":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTE3MzE0NzksInN1YiI6IndlYmFkbWluIiwiZW1haWwiOiJ3ZWJhZG1pbkBsb2NhbGRvbWFpbi5sb2NhbCIsInJvbGVzIjpbInN1cGVyYWRtaW4iLCJndWVzdCIsImFub255bW91cyJdLCJvcmlnaW4iOiJsb2NhbGhvc3QifQ.OmFOCu-UJdx16FYLa2ezr7WRmOdUbgrQadhfk1tN4AliIwu69x9TLgzoke_Cr3TqzvMjlQDd22r-3DHBXuzllw"}
```
