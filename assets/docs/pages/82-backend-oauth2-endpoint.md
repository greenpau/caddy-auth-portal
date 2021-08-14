### OAuth 2.0 Endpoint Delayed Start

The following configuration allows delaying getting key material of upstream
OAuth 2.0 server.

```
      backends {
        google_oauth2_backend {
          method oauth2
          ...
          delay_start 5
```

This would delay querying the upstream server for 5 seconds.

[:arrow_up: Back to Top](#table-of-contents)

### OAuth 2.0 Endpoint Retry Attempts

The following configuration permits for retries when getting key material of
upstream OAuth 2.0 server.

```
      backends {
        google_oauth2_backend {
          method oauth2
          ...
          retry_attempts 3
          retry_interval 10
```

If unsuccessful at reaching a remote OAuth 2.0 server, the plugin would
try connecting 2 more times at 10 second intervals.

[:arrow_up: Back to Top](#table-of-contents)

<!--- end of section -->
