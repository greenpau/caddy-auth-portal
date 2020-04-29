# caddy-auth-forms

<a href="https://github.com/greenpau/caddy-auth-forms/actions/" target="_blank"><img src="https://github.com/greenpau/caddy-auth-forms/workflows/build/badge.svg?branch=master"></a>
<a href="https://pkg.go.dev/github.com/greenpau/caddy-auth-forms" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
<a href="https://caddy.community" target="_blank"><img src="https://img.shields.io/badge/community-forum-ff69b4.svg"></a>

Form-Based Authentication Plugin for for [Caddy v2](https://github.com/caddyserver/caddy).


## SQLite Backend

First, initialize a database, e.g.:

```bash
$ sqlite3 assets/backends/sqlite3/sqlite3.db < assets/backends/sqlite3/create_db.sql
```

After the successful completion of the above command, the
`file` command returns the following information

```bash
$ file assets/backends/sqlite3/sqlite3.db
assets/backends/sqlite3/sqlite3.db: SQLite 3.x database
```

Next, create an administrator user for the database:

```bash

```

Related error:

```json
{
  "level": "error",
  "ts": 1588190071.9516814,
  "logger": "http.authentication.providers.forms",
  "msg": "sqlite3 database file does not exists",
  "db_path": "assets/backends/sqlite3/sqlite3.db"
}
```
