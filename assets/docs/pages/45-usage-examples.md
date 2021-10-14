
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
    authp {
      crypto default token lifetime 3600
      crypto key sign-verify 0e2fdcf8-6868-41a7-884b-7308795fc286
      backends {
        local_backend {
          method local
          path /etc/gatekeeper/auth/local/users.json
          realm local
        }
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
    authorize {
      primary yes
      crypto key verify 0e2fdcf8-6868-41a7-884b-7308795fc286
      set auth url /auth
      allow roles authp/admin authp/user authp/guest
      allow roles superadmin
    }
    uri strip_prefix /prometheus
    reverse_proxy http://127.0.0.1:9080
  }

  route /alertmanager* {
    authorize
    uri strip_prefix /alertmanager
    reverse_proxy http://127.0.0.1:9083
  }

  route /myapp* {
    authorize
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
        template login "/etc/gatekeeper/ui/login.template"
        template portal "/etc/gatekeeper/ui/portal.template"
        logo url "https://caddyserver.com/resources/images/caddy-circle-lock.svg"
        logo description "Caddy"
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
    authorize
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
