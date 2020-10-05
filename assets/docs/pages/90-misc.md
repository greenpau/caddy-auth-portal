
## Miscellaneous

### Binding to Privileged Ports

It may be necessary to bind Caddy to privileged port, e.g. 80 or 443.
Grant the `cap_net_bind_service` capability to the Caddy binary, e.g.:

```bash
sudo systemctl stop gatekeeper
sudo rm -rf /usr/local/bin/gatekeeper
sudo cp bin/caddy /usr/local/bin/gatekeeper
sudo setcap cap_net_bind_service=+ep /usr/local/bin/gatekeeper
sudo systemctl start gatekeeper
```

[:arrow_up: Back to Top](#table-of-contents)

### Recording Source IP Address in JWT Token

The `enable source ip tracking` Caddyfile directive instructs
the plugin to record the source IP address when issuing claims.

```
localhost {
  route /auth* {
    auth_portal {
      ...
      enable source ip tracking
      ...
```

This could be useful to force re-authentication when the client IP
address changes.
