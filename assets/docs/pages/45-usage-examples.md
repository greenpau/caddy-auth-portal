
## Usage Examples

### Secure Prometheus

The following `Caddyfile` secures Prometheus/Alertmanager services:

```Caddyfile
{
  http_port     8080
  https_port    8443
  debug
}

localhost:8443 {
  route /auth* {
    auth_portal {
      path /auth
      backends {
        local_backend {
          method local
          path /etc/gatekeeper/auth/local/users.json
          realm local
        }
      }
      jwt {
        token_name access_token
        token_secret 0e2fdcf8-6868-41a7-884b-7308795fc286
        token_issuer e1008f2d-ccfa-4e62-bbe6-c202ec2988cc
      }
      ui {
        links {
          "Prometheus" /prometheus
          "Alertmanager" /alertmanager
          "My App" /myapp
        }
      }
    }
  }

  route /prometheus* {
    jwt {
      primary yes
      trusted_tokens {
        static_secret {
          token_name access_token
          token_secret 0e2fdcf8-6868-41a7-884b-7308795fc286
          token_issuer e1008f2d-ccfa-4e62-bbe6-c202ec2988cc
        }
      }
      auth_url /auth
      allow roles anonymous guest admin
      allow roles superadmin
    }
    uri strip_prefix /prometheus
    reverse_proxy http://127.0.0.1:9080
  }

  route /alertmanager* {
    jwt
    uri strip_prefix /alertmanager
    reverse_proxy http://127.0.0.1:9083
  }

  route /myapp* {
    jwt
    respond * "myapp" 200
  }

  route /version* {
    respond * "1.0.0" 200
  }

  route {
    redir https://{hostport}/auth 302
  }
}
```

If you would like to style the UI differently, then specify your
templates and settings:

```
      ui {
        login_template "/etc/gatekeeper/ui/login.template"
        portal_template "/etc/gatekeeper/ui/portal.template"
        logo_url "https://caddyserver.com/resources/images/caddy-circle-lock.svg"
        logo_description "Caddy"
        links {
          "Prometheus" /prometheus
          "Alertmanager" /alertmanager
          "My App" /myapp
        }
      }
```

In fact, if you are not going to display any links, then
remove the `ui` section and use an auto-redirect feature.

[:arrow_up: Back to Top](#table-of-contents)

### Secure Kibana

First, add the following line in `/etc/kibana/kibana.yml`. It must match the
the prefix used when proxying traffic through:

```
server.basePath: "/elk"
```

Next, add the following route in you Caddyfile:

```
  route /elk* {
    jwt
    uri strip_prefix /elk
    reverse_proxy KIBANA_IP:5601
  }
```

Also, add the link to Kibana in `ui` section of Caddyfile:

```
      ui {
        ...
        links {
          ...
          "Kibana" /elk/
          ...
        }
      }
```

[:arrow_up: Back to Top](#table-of-contents)

<!--- end of section -->
