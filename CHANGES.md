# Changes vs Certbot

This file tracks every behavior in **go-certbot** that differs from upstream
[Certbot 5.x](https://github.com/certbot/certbot). The project's goal is
drop-in compatibility, so this file should stay short. Anything not listed
here should behave identically to Certbot.

## Phase 3 (current)

### Implemented

- `certificates` verb — iterates `renewal/*.conf`, prints
  `Certificate Name / Serial Number / Key Type / Identifiers /
  Expiry Date / Certificate Path / Private Key Path` in Certbot's
  format. Status is `VALID: N days` / `VALID: N hour(s)` /
  `INVALID: EXPIRED`. Filters: `--cert-name`, `-d`, `--ip-address`.
- `delete` verb — `--cert-name` removes `live/<name>/`,
  `archive/<name>/`, and `renewal/<name>.conf`. The renewal conf is
  renamed to `.deleted` first so a crash leaves a clear marker
  rather than half-baked state.
- `revoke` verb — `--cert-name` or `--cert-path`, optional
  `--reason {unspecified,keycompromise,affiliationchanged,
  superseded,cessationofoperation}`, optional `--delete-after-revoke`
  to also drop on-disk files. Backed by lego's `RevokeWithReason`.
- Account verbs:
  - `register` — explicit account creation (no-op if one already
    exists for the server).
  - `show_account` — prints id, ACME URL, contacts, creation
    host/date.
  - `update_account` — PATCHes the contact email at the ACME server.
  - `unregister` — calls `DeleteRegistration` to deactivate, then
    removes the local account directory.

## Phase 2

### Implemented

- `renew` verb: iterates `renewal/*.conf`, restores `[renewalparams]` with
  CLI-overridable merge semantics matching Certbot's `set_by_user` gating,
  parses `renew_before_expiry` (English-language durations: "30 days",
  "6 weeks", "3 months", bare integers = days), skips certs that aren't
  near expiry (default window: 30 days) unless `--force-renewal` is set.
- `reconfigure` verb: writes user-set flags back to a renewal `.conf`
  without re-issuance.
- `webroot` plugin: writes the http-01 file into one or more webroot
  directories. Single `--webroot-path` applies to all domains; N paths for
  N domains produces a per-domain map (Certbot semantics).
- `manual` plugin: runs `--manual-auth-hook` and `--manual-cleanup-hook`
  scripts with Certbot's env contract (`CERTBOT_DOMAIN`,
  `CERTBOT_VALIDATION`, `CERTBOT_TOKEN`, `CERTBOT_AUTH_OUTPUT`). This is
  the bridge that lets third-party DNS plugins keep working — write a
  hook script that calls your favorite tool.
- Hooks framework: `--pre-hook` / `--post-hook` / `--deploy-hook` plus
  directory hooks under `renewal-hooks/{pre,post,deploy}/`. Deploy hooks
  receive `RENEWED_LINEAGE` and `RENEWED_DOMAINS`. Pre-hook runs once per
  invocation before any challenge work; post-hook always runs after
  (success or failure); deploy-hook only on successful issuance/renewal.
  Hook commands are validated for executability before invocation
  unless `--disable-hook-validation` is set.
- EFF mailing-list subscription via `--eff-email` (POST to
  `supporters.eff.org/subscribe/certbot`, same form Certbot uses).
  `--no-eff-email` and `--dry-run` suppress.

## Phase 1

### Implemented

- `certonly --standalone -d <domain>` end-to-end against any ACME-compatible
  server (Let's Encrypt, Pebble, internal CAs). Uses [lego v5](
  https://github.com/go-acme/lego) for the ACME protocol.
- On-disk state under `--config-dir` (default `/etc/letsencrypt`) matches
  Certbot 5.x exactly:
  - `accounts/<server_path>/<account_id>/{regr.json,private_key.json,meta.json}`
  - `live/<certname>/{cert,privkey,chain,fullchain}.pem` (relative symlinks
    into `archive/`)
  - `archive/<certname>/{cert,privkey,chain,fullchain}<N>.pem`
  - `renewal/<certname>.conf` with `[renewalparams]`
- `cli.ini` is read from `<config-dir>/cli.ini` and
  `$XDG_CONFIG_HOME/letsencrypt/cli.ini` in that order; unknown keys are
  ignored (forward-compatible with Certbot configs for unimplemented flags).
- Account id derivation matches Certbot: lowercase hex MD5 of the
  SubjectPublicKeyInfo PEM. Existing Certbot accounts on disk are loaded
  unchanged.

### Not yet implemented (verbs return a clear "planned for Phase N" error)

| Verb | Planned phase |
| --- | --- |
| `run` (the default) | Phase 1 final (after installers) |
| `install`, `enhance`, `rollback` | Phase 5 (nginx) / Phase 6 (apache) |

Plugins not yet implemented (using them returns a clear error):

| Plugin | Planned phase |
| --- | --- |
| `dns-{cloudflare,digitalocean,dnsimple,dnsmadeeasy,gehirn,google,linode,luadns,nsone,ovh,rfc2136,route53,sakuracloud}` | Phase 4 (wraps lego providers) |
| `nginx` | Phase 5 |
| `apache` | Phase 6 |

### Breaking changes (documented and intentional)

These are the differences vs. Certbot 5.x that won't be reconciled even once
all phases land:

- **Single static binary; no Python runtime.** Install go-certbot by
  dropping the binary in your PATH. There is no `pip install certbot`, no
  `certbot-auto`, and no `letsencrypt-auto-source`.

- **No third-party plugin loading.** Certbot discovers plugins through the
  `certbot.plugins` setuptools entry-point group; that mechanism cannot
  work for a static Go binary. The 13 DNS plugins that ship with Certbot
  upstream are re-implemented in-tree (each is a thin wrapper over the
  corresponding lego provider) — see Phase 4. Users of third-party
  Certbot Python plugins (the various unofficial DNS plugins,
  `certbot-dns-route53-bigip`, etc.) cannot use this version. Mitigation:
  external plugins can still drive issuance via `--manual` plus
  `--manual-auth-hook` / `--manual-cleanup-hook` scripts (once Phase 2
  lands).

- **`dns-google` credentials.** Certbot's `dns-google` plugin reads a
  service-account JSON via `--dns-google-credentials`; lego's `gcloud`
  provider reads `GCE_PROJECT` and `GOOGLE_APPLICATION_CREDENTIALS`. We
  accept Certbot's flag and translate to lego's environment at runtime,
  but users who set Google credentials via Application Default Credentials
  on a GCE/GKE instance may see different behavior; documented when
  Phase 4 lands.

- **Reduced Augeas fidelity** (when Apache lands in Phase 6). Certbot uses
  python-augeas to parse Apache configuration. The Go rewrite ports the
  parser; tiny formatting differences in generated Apache config
  (whitespace, quote style) are expected.

- **No `certbot.ocsp` Python module compatibility**. Certbot exposes
  `certbot.ocsp` as a (deprecated) public API; nothing in Go can import a
  Python module, so this is moot — listed here only for completeness.

- **EFF email subscription** prompts in noninteractive mode default to the
  same answer as Certbot (no subscription); the prompt for the
  interactive case is reimplemented in Phase 2 along with webroot/manual.

### Compatibility-checked but unchanged

These are areas where the rewrite produces output equivalent to Certbot's:

- `accounts/<server_path>/<id>/{regr.json,private_key.json,meta.json}` is
  round-trippable between Certbot and go-certbot. Switching back to Certbot
  after running go-certbot leaves accounts and lineages usable.
- `renewal/<certname>.conf` format: the `[renewalparams]` section uses the
  same keys and value styles Certbot writes, so `certbot renew` against a
  go-certbot-produced config will work.
- Default paths: `/etc/letsencrypt`, `/var/lib/letsencrypt`,
  `/var/log/letsencrypt` on Linux/macOS; `C:\Certbot`, `C:\Certbot\lib`,
  `C:\Certbot\log` on Windows. Permission modes (0755 for directories,
  0600 for private keys) match.
