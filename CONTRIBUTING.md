# Contributing Guidelines

## Contributor License Agreements

I'd love to accept your pull request! Before I can take them, we have to jump a
couple of legal hurdles.

***NOTE***: Only original source code from you and other people that have
signed the CLA can be accepted into the main repository.

Please fill out either the individual or corporate Contributor License Agreement (CLA).
* If you are an individual writing original source code and you're sure you own the
  intellectual property, then you'll need to sign an [individual CLA](/assets/cla/individual_cla.md).
* If you work for a company that wants to allow you to contribute your work, then
  you'll need to sign a [corporate CLA](/assets/cla/corporate_cla.md).

Follow either of the two links above to access the appropriate CLA. Next, if you are
ready to accept, add the following text in the body your first commit message.

* For Individual CLA:

      I hereby consent to the Individual CLA provided in assets/cla/individual_cla.md

* For Corporate CLA:

      I hereby consent to the Corporate CLA provided in assets/cla/corporate_cla.md

## Pull Request Checklist

Before sending your pull requests, make sure you followed this list.

1. Open an issue to discuss your PR
2. Ensure you read appropriate Contributor License Agreement (CLA)
3. Run unit tests

## Development Environment

The contribution to `portal` and `jwt` plugins requires setting up a development
environment. The following steps allow developers to test Caddy server with
the plugins using local source code.

First, designate directory for building caddy with plugins, e.g. `tmpcaddydev`.

```bash
mkdir -p ~/tmpcaddydev
cd ~/tmpcaddydev
```

Second, fork the following repositories in Github into to your own Github
handle, e.g. `anonymous`:

* `https://github.com/greenpau/caddy-auth-portal` => `https://github.com/anonymous/caddy-auth-portal`
* `https://github.com/greenpau/caddy-auth-jwt` => `https://github.com/anonymous/caddy-auth-jwt`
* `https://github.com/greenpau/caddy-trace` => `https://github.com/anonymous/caddy-trace`

Provided you are in `tmpcaddydev` directory, clone the forked repositories:

```bash
git clone git@github.com:anonymous/caddy-auth-portal.git
git clone git@github.com:anonymous/caddy-auth-jwt.git
git clone git@github.com:anonymous/caddy-trace.git
```

Next, browse to `caddy-auth-portal` and run the following `make` command to install
various dependencies:

```bash
cd caddy-auth-portal
make dep
```

Once all the necessary packages are installed, you should be ready to compile
`caddy` using the local source code. Run:

```bash
make
```

The above make command creates `xcaddy-caddy-auth-portal` directory in `tmpcaddydev`.
Then, it starts building `caddy` and referencing locally sources plugins.

After the build, the resultant binary will be in `bin/` directory. You can
then test it with your own configuration files.

```bash
bin/caddy run -config /etc/gatekeeper/Caddyfile | jq
```
