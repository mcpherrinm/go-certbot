# go-certbot

Experimental new major version of [Certbot](https://github.com/certbot/certbot),
rewritten in Go on top of [lego v5](https://github.com/go-acme/lego).

## Goals

- Drop-in compatibility with existing Certbot installations: same CLI flags,
  configuration file format, account/cert state on disk, and integration with
  web servers (nginx, Apache).
- Auto-upgrade path: users currently running Certbot should be able to switch
  to this version without manual migration.
- Only minor, fully documented breaking changes permitted (see `CHANGES.md`).

## Status

Planning phase. The upstream Certbot repository is vendored as a git submodule
under `vendor/certbot/` for reference.
