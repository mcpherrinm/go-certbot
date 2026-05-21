# go-certbot

Experimental new major version of [Certbot](https://github.com/certbot/certbot),
rewritten in Go on top of [lego v5](https://github.com/go-acme/lego).

## Goals

- Drop-in compatibility with existing Certbot installations: same CLI flags,
  configuration file format, account/cert state on disk, and integration with
  web servers (nginx, Apache).
- Auto-upgrade path: users currently running Certbot should be able to switch
  to this version without manual migration.
- Only minor, fully documented breaking changes permitted (see [`CHANGES.md`](
  CHANGES.md)).

## Status

**Phase 2.** Building on Phase 1, this version adds the `renew` and
`reconfigure` verbs, `webroot` and `manual` authenticators, the full
hooks framework (pre / post / deploy commands and
`renewal-hooks/{pre,post,deploy}/` directories), and EFF email
subscription. Other verbs (`certificates`, `delete`, `revoke`,
account management) and the nginx/apache/DNS plugins return a clear
"planned for Phase N" error. See [`CHANGES.md`](CHANGES.md) for the
rollout plan.

The upstream Certbot source tree is vendored as a git submodule under
`reference/certbot/` for cross-reference. (We avoid the Go-reserved
`vendor/` directory name.) After cloning, run:

```
git submodule update --init reference/certbot
```

## Building

```
go build ./...
./go-certbot --help
```

## Trying it (Phase 1)

```
./go-certbot certonly --standalone \
    --agree-tos --email you@example.com \
    --staging \
    -d example.test \
    --config-dir /tmp/le --work-dir /tmp/le/work --logs-dir /tmp/le/logs
```

For local development without a public domain, point `--server` at
[Pebble](https://github.com/letsencrypt/pebble) and add
`--http-01-port 5002 --no-verify-ssl`.

## Layout

```
internal/
  config/                NamespaceConfig analog + paths
  account/               JWK, MD5 id, accounts/<server>/<id>/ storage
  storage/               live/archive symlink lineage
  storage/renewalconf/   renewal/*.conf reader/writer
  plugins/               plugin registry + interfaces
  plugins/standalone/    http-01 server (wraps lego)
  client/                lego v5 wrapper
  verbs/                 one file per subcommand (certonly + stubs)
  cmd/                   CLI parsing and dispatch
reference/certbot/       upstream Certbot as a submodule, reference only
```
