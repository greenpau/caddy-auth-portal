
## Authorization Cookie

The following `Caddyfile` settings define the scope of the cookies issued by
the plugin. Specifically, what URLs the cookies should be sent to.
See [MDN - Using HTTP cookies - Define where cookies are sent](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
for more information.

* `cookie_domain`: adds the **Domain** attribute to a cookie. It determines
  which hosts are allowed to receive the cookie.
* `cookie_path`: adds the **Path** attribute to a cookie. It determines the
  URL path that must exist in the requested URL in order to send
  the Cookie header.

The plugin sends JWT token via a the cookie.

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

[:arrow_up: Back to Top](#table-of-contents)

<!--- end of section -->