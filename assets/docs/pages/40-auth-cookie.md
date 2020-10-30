
## Authorization Cookie

### Intra-Domain Cookies

The following `Caddyfile` settings define the scope of the cookies issued by
the plugin. Specifically, what URLs the cookies should be sent to.
See [MDN - Using HTTP cookies - Define where cookies are sent](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
for more information.


* `cookie_domain`: adds the **Domain** attribute to a cookie. It determines
  which hosts are allowed to receive the cookie.
* `cookie_path`: adds the **Path** attribute to a cookie. It determines the
  URL path that must exist in the requested URL in order to send
  the Cookie header.

### JWT Tokens

The plugin sends JWT token via the cookie.

* `token_name`: specifies the names of the cookie with authorization credentials

By default the lifetime of the token is 15 minutes. The `token_lifetime`
can be used to change it to 1 hour (3600 seconds).

```
      jwt {
        token_name access_token
        token_secret 0e2fdcf8-6868-41a7-884b-7308795fc286
        token_issuer e1008f2d-ccfa-4e62-bbe6-c202ec2988cc
        token_lifetime 3600
      }
```

The issued JWT token could be of two types:

1. `HS512`: signed using shared secret key
2. `RS512`: signed using private PEM key

The `HS512` is being configured with `token_secret`

```
      jwt {
        ...
        # token_secret <shared_key>
        token_secret 0e2fdcf8-6868-41a7-884b-7308795fc286
        ...
      }
```

The `RS512` is being configured with `token_rsa_file` directive:

```
      jwt {
        ...
        token_rsa_file <key_id> <file_path>
        token_rsa_file Hz789bc303f0db /etc/gatekeeper/auth/jwt/sign_key.pem
        ...
      }
```

If necessary, generate the signing key:

```bash
$ openssl genrsa -out /etc/gatekeeper/auth/jwt/sign_key.pem 2048
Generating RSA private key, 2048 bit long modulus (2 primes)
.....................................................................................................................+++++
....+++++
e is 65537 (0x010001)
```

#### JWT Signing Method

By default, the plugin uses HS512 (shared secret) and RS512 (public/private keys) for
the signing of JWT tokens. User `token_sign_method` to change the algorithm, e.g.

```
      jwt {
        ...
        token_secret 0e2fdcf8-6868-41a7-884b-7308795fc286
        token_sign_method HS256
        ...
      }
```

or:

```
      jwt {
        ...
        token_rsa_file Hz789bc303f0db /etc/gatekeeper/auth/jwt/sign_key.pem
        token_sign_method RS256
        ...
      }
```

[:arrow_up: Back to Top](#table-of-contents)

<!--- end of section -->
