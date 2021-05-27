module github.com/greenpau/caddy-auth-portal

go 1.15

require (
	github.com/caddyserver/caddy/v2 v2.3.0
	github.com/crewjam/saml v0.4.5
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-ldap/ldap v3.0.3+incompatible
	github.com/google/go-cmp v0.5.5
	github.com/greenpau/caddy-auth-jwt v1.2.7
	github.com/greenpau/caddy-trace v1.1.6
	github.com/greenpau/go-identity v1.0.23
	github.com/iancoleman/strcase v0.1.3
	github.com/satori/go.uuid v1.2.0
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20200728195943-123391ffb6de
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
)

replace github.com/greenpau/caddy-auth-jwt v1.2.7 => /home/greenpau/dev/go/src/github.com/greenpau/caddy-auth-jwt

replace github.com/greenpau/caddy-trace v1.1.6 => /home/greenpau/dev/go/src/github.com/greenpau/caddy-trace

replace github.com/greenpau/go-identity v1.0.23 => /home/greenpau/dev/go/src/github.com/greenpau/go-identity
