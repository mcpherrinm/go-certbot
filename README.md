# go-certbot

This is an experiment in makign a clone of Certbot in Go based on Lego.

The code is all AI-generated, and is not intended to be used.

## Goals

- Drop-in compatibility with existing Certbot installations: same CLI flags,
  configuration file format, account/cert state on disk, and integration with
  web servers (nginx, Apache).
- Auto-upgrade path: users currently running Certbot should be able to switch
  to this version without manual migration.
- Only minor, fully documented breaking changes permitted (see [`CHANGES.md`](
  CHANGES.md)).

## Status

**1.0.0 — feature-complete.** Every Certbot 5.x verb and bundled
plugin now has a working implementation, end-to-end issuance is
verified against [Pebble](https://github.com/letsencrypt/pebble) in
`tests/e2e/`, and a `rollback` verb plus a file-snapshot checkpoint
system reverts the most recent config changes. See
[`CHANGES.md`](CHANGES.md) for the full list, including the small,
documented breaking changes vs upstream Certbot (single static
binary; no third-party Python plugin loading; a few minor scope
limits in the nginx/apache configurators).

To run the end-to-end suite locally:

```
go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
go test ./tests/e2e -v
```

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
