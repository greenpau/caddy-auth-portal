FROM caddy:builder AS builder
LABEL maintainer="greenpau"
LABEL org.opencontainers.image.source https://github.com/greenpau/caddy-auth-portal

RUN xcaddy build \
    --with github.com/greenpau/caddy-authorize \
    --with github.com/greenpau/caddy-auth-portal \
    --with github.com/caddy-dns/cloudflare

FROM caddy:latest

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
