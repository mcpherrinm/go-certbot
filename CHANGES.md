# Changes vs Certbot

This file tracks every behavior in **go-certbot** that differs from upstream
[Certbot 5.x](https://github.com/certbot/certbot). The project's goal is
drop-in compatibility, so this file should stay short. Anything not listed
here should behave identically to Certbot.

## Phase 12 (current) — go-certbot 1.4.0 — review-3 sweep

Third comprehensive code review surfaced ~40 additional differences. The
highest-impact P0/P1 fixes land here.

### Account storage (P0 — broke byte-equivalence)

- **JSON separators**: every account file (`regr.json`, `meta.json`,
  `private_key.json`) is now byte-equivalent to Python's `json.dumps`
  default: keys and values separated by `, ` and `: ` (with spaces).
- **JWK field order** matches josepy exactly: `kty` is appended *last*
  (RSA: `n,e,d,p,q,dp,dq,qi,kty`; EC: `d,x,y,crv,kty`).
- **Thumbprint** now hashes the RFC 7638 canonical JSON of the JWK's
  required public fields only (sorted lex, no spaces). `show_account`'s
  Account Thumbprint line is now byte-equivalent to Certbot's.

### Renewal/config

- `parseRenewBefore "0 days"` now accepts as "always renew" (Certbot via
  parsedatetime returns 0 too).
- `autorenew = False` now skips the lineage on `renew`.
- `reconfigure --deploy-hook ""` clears the hook (via DeleteParam) rather
  than leaving an empty stub.

### CLI

- **Slice duplication fix**: argv values are now snapshot/restored over
  ini-loaded values instead of double-parsing argv (which appended).
- `--directory-hooks` / `--no-directory-hooks` and `--validate-hooks` /
  `--no-validate-hooks` flags wired (fields existed since phase 10).
- `--eff-email` tri-state now properly resolves into `*bool`.
- `--dry-run` side effects applied: implies `--staging` + `--break-my-certs`;
  auto-agrees TOS + sets `--register-unsafely-without-email` when no email.
- `--staging` + custom `--server` is now rejected.
- Apache plugin flags wired: `--apache-bin`, `--apache-enmod`,
  `--apache-dismod`, `--apache-le-vhost-ext`, `--apache-vhost-root`,
  `--apache-logs-root`, `--apache-challenge-location`,
  `--apache-handle-modules`, `--apache-handle-sites`.
- `--nginx-sleep-seconds` wired; default 1, honored in testAndReload.
- Validations: `--key-type` choices, `--elliptic-curve` choices,
  `--max-log-backups` non-negative, `--user-agent-comment` rejects `()`.

### Hooks / webroot / EFF

- **Webroot chowns created prefix dirs** to match webroot owner (best-effort).
- **PostEnv truncates** `RENEWED_DOMAINS`/`FAILED_DOMAINS` at 16 KiB with
  a warning, matching `hooks.py:173-179`.
- **EFF subscription is now non-fatal** (errors go to stderr, callers
  ignore). Added a `User-Agent` header.
- **`eff.Decide(cfg)`** wires the interactive `_want_subscription`
  prompt when `--eff-email` / `--no-eff-email` aren't set.
- **`display.Email`** now accepts a blank line as "skip" (matches
  `display_ops.get_email`); Register switches to
  `--register-unsafely-without-email` when the user hits Enter.

### Verbs / display

- `enhance --redirect` now supported on both nginx and apache. Nginx
  uses the per-domain `if ($host = X)` block; Apache uses
  `RewriteCond %{SERVER_NAME} =name [OR]` per name plus RewriteRule.

### Standalone

- Bind errors now distinguish `EACCES` ("permission denied, try sudo or
  --http-01-port") from `EADDRINUSE` ("address already in use") with
  Certbot-style helpful messages.

### Signal handling

- The SIGINT goroutine no longer kills tests via stale `os.Exit(130)`
  after the handler exited cleanly. It now checks a `handlerDone`
  channel before scheduling the force-exit timer.

### Apache

- **Marker text** is now placed *inside* each cloned vhost via a
  per-vhost UUID comment (`# DO NOT REMOVE - Managed by Certbot,
  VirtualHost id: <uuid4>`), matching Certbot's vhost-id detection.
- **`RewriteCond %{SERVER_NAME} =name [OR]`** per-domain guard added
  before the redirect RewriteRule.
- **Per-OS coverage** corrected: Alpine `Ctl=apachectl`, Arch
  `VHostRoot=/etc/httpd/conf`, plus Darwin (`/etc/apache2/other`) and
  Void (`/etc/apache/extra`).

### Nginx

- **Challenge conf** now lives in `config_dir/le_http_01_cert_challenge.conf`
  (matches Certbot's `http_01.py:46-47`) instead of the work-dir scratch.
- **Redirect blocks prepend** instead of append (`insert_at_top=True`).
- **`ssl_dhparam` install**: `<config_dir>/ssl-dhparams.pem` (the
  RFC 7919 ffdhe2048 group Certbot ships) is now written, with
  `ssl_dhparam <path>;` added to every SSL server block.
- **Historical SHA whitelist** prevents clobbering user-modified
  `options-ssl-nginx.conf` / `ssl-dhparams.pem`.

### DNS plugins

- `dns_common` permission warning now matches Certbot's mask
  (`0o007` — world-readable only); was overly strict at `0o077`.

## Phase 11 — go-certbot 1.3.0 — deep parity

Picks up the architectural items deferred from phase 10. Every change here
brings go-certbot closer to byte-equivalent on-disk state with Certbot.

### Apache

- **Version detection** via `apachectl -v`; forks chain handling at 2.4.8:
  emits `SSLCertificateChainFile` only on older Apache (where chain inside
  fullchain isn't supported), strips stale `SSLCertificateChainFile`
  directives on newer Apache when reinstalling.
- **`vhost_root` honored** for SSL-clone destination. New `-le-ssl.conf`
  files land in `/etc/apache2/sites-available/` (Debian),
  `/etc/httpd/conf.d/` (RHEL/Fedora), `/etc/apache2/vhosts.d/` (Gentoo/
  SUSE), etc., per the per-OS table.
- **Debian `sites-enabled` symlink**: when the new vhost lands under
  `sites-available/`, also symlink it into `sites-enabled/` so Apache
  actually loads it (in-process equivalent of `a2ensite`).

### Nginx

- **HTTP-01 architecture rewritten to match Certbot**:
  - Writes a dedicated `<work_dir>/le_http_01_cert_challenge.conf` with
    one `server { … return 200 "<keyAuth>"; }` block per challenge.
  - Adds a single `include` line to nginx.conf's `http {}` block plus
    `server_names_hash_bucket_size 128` (matches `http_01.py:72-244`).
  - Injects only a `rewrite ^(/.well-known/acme-challenge/.*) $1 break;`
    at the TOP of each matched server (no more whole `location` block
    inside user vhosts).
  - Falls back to a default-server fallback when no `server_name` matches
    (so IP-address-SAN issuance under RFC 8738 works).
  - Cleanup undoes the rewrite, the include, the bucket-size, and
    deletes the challenge conf.
- **Redirect uses `if ($host = X) { return 301 ... }`** prepended to
  existing HTTP vhosts (per-domain guard), matching
  `configurator.py:898-953,1265-1278`. If no HTTP vhost serves the
  domain, we log and skip — matches Certbot's "no matching insecure
  server blocks" behavior. The previous whole-`:80`-server clone is
  gone (could loop behind Cloudflare etc.).

### Signal handling

- **SIGINT/SIGTERM rollback**: `checkpoint.MarkClean()` is called by every
  installer after a successful reload; on signal exit, the in-flight
  checkpoint is restored automatically (`checkpoint.RestoreInFlight`).
  Prints Certbot's `Exiting due to user request.` message. A 5-second
  hard-deadline goroutine force-exits if the handler is hung.

### Reverter layout

- **Checkpoint dirs now byte-identical to Certbot's** so
  `certbot rollback` reads go-certbot's checkpoints (and vice-versa):
  - `<work_dir>/backups/<unix-timestamp>/`
  - `FILEPATHS` — newline-separated original paths
  - `CHANGES_SINCE` — label
  - `NEW_FILES` — files we created (rollback deletes them)
  - `<basename>_<idx>` — backed-up content, indexed by FILEPATHS line.

### Display

- **`Menu(prompt, items, default)`**, `Checklist(prompt, items)`,
  `DirectorySelect(prompt, default)` added; used by interactive
  `--cert-name` selection in delete/install/enhance/reconfigure.

## Phase 10 — go-certbot 1.2.0 — drop-in parity sweep

Second comprehensive code review surfaced ~150 functional differences. This
release ports the highest-impact fixes across every surface.

### Renewal/config compatibility

- **DNS plugin keys persisted and restored**: `dns_<plugin>_credentials`
  and `dns_<plugin>_propagation_seconds` round-trip through
  `renewal.conf`, so DNS-plugin lineages renew non-interactively.
- **`ip_addresses` SAN preserved across renewals** (RFC 8738).
- **VAR_MODIFIERS honored**: `--server` invalidates the conf-recorded
  account; `--staging`/`--dry-run`→`--server`; `--webroot-path`→
  `--webroot-map`.
- **Short-lived-cert renewal math**: certs with lifetime ≤ 10 days renew
  at NotBefore + lifetime/2 (matches `_default_renewal_time`).
- **Hook commands with commas** are now correctly quoted so configobj
  re-parses them as strings, not lists.
- **`reconfigure` rejects `--server`/`--account`/`--domain` changes**
  and writes deploy-hook under the historic `renew_hook` key.

### Hooks & manual plugin

- **post-hook env**: `RENEWED_DOMAINS`/`FAILED_DOMAINS` now exported.
- **pre-hook deduplicated** across lineages in one `renew` run.
- **Directory hooks gated by `--directory-hooks`/`--no-directory-hooks`**.
- **`~`-suffix backup files** skipped in directory-hook dispatch.
- **Manual plugin**: `CERTBOT_ALL_DOMAINS`/`_ALL_IDENTIFIERS` now
  **comma**-separated. `CERTBOT_REMAINING_CHALLENGES` computed
  per-Present. `CERTBOT_TOKEN` omitted on DNS-01. `CERTBOT_VALIDATION`
  contains base64url(sha256(keyAuth)) for DNS-01 (was raw keyAuth).
  `CERTBOT_AUTH_OUTPUT` stripped.

### Webroot plugin

- Multi-`-w` without an explicit map accepted; last `-w` is the
  fallback for unmapped domains.
- All prefix dirs we created are tracked for cleanup.
- `-w` values are abspath'd before storing.

### Verbs

- **TOS interactive prompt** when `--agree-tos` not set and interactive.
- **`revoke` prompts to delete the lineage** (default Yes).
- **`delete`/`install`/`enhance`/`reconfigure` prompt for `--cert-name`**.
- **`renew` report**: side-frame banner + Congratulations / N renew
  failure(s) summary; `Processing <conf>` per lineage; expiry date on
  not-yet-due lineages.
- **`unregister` prompt defaults to Yes**; removes empty server-parent.
- **`certonly` success block matches Certbot's `_report_new_cert`**.
- **`update_account`** splits comma-separated emails.
- **`plugins`** verb no longer prints the Phase 5/6 placeholder.

### Account storage

- **`Load(id)` falls back to LE_REUSE_SERVERS predecessor** dir +
  per-account symlinks for v01→v02 migrations.
- **`Save()` fails loudly** if `private_key.json` exists (was silent
  no-op).

### CLI flags

- Negators: `--no-hsts`, `--no-uir`, `--no-staple-ocsp`,
  `--no-delete-after-revoke`.
- `--disable-hook-validation` properly flips `validate_hooks`.
- Short aliases: `-a`, `-i`, `-q`.
- Verb aliases: `auth` (= `certonly`), `everything` (= `run`).
- `--preferred-challenges` normalizes `http`/`http_01`→`http-01`,
  `dns`/`dns_01`→`dns-01`.
- `--must-staple` implies `--staple-ocsp`.
- `--reason` validated against Certbot's accepted set.
- `--quiet` implies `--non-interactive`.

### Apache plugin

- **`options-ssl-apache.conf` snippet installed** and `Include`d from
  every SSL vhost — brings SSLProtocol/SSLCipherSuite/SSLHonorCipherOrder
  to Mozilla-intermediate (vs Apache defaults).
- **Marker text** fixed to `# DO NOT REMOVE - Managed by Certbot` for
  mixed-tool interop.
- **RHEL/Fedora `Ctl` is `apachectl`** (was `httpd`), so `configtest`/
  `graceful` work.
- **`mod_socache_shmcb` enabled** (required by `SSLStaplingCache`).
- **Per-OS coverage extended**: Fedora, Arch/Manjaro, openSUSE with
  `VHostRoot` recorded.

### Nginx plugin

- **server_name matching** supports regex (`~^…`), trailing wildcards
  (`mail.*`), leading-dot (`.example.com`), leading wildcards
  (`*.example.com`).
- **Post-reload 1s sleep** to avoid challenge-verification races.
- **macOS/BSD default config root** honored.

### Infrastructure

- **Log file** at `<logs_dir>/letsencrypt.log` with 1 MiB rotation +
  `--max-log-backups`. Stderr default threshold WARNING (matches
  Certbot); file handler captures DEBUG. `Saving debug log to …`
  banner.
- **Process lock**: advisory file lock (`.certbot.lock`) on
  config/work/logs dirs so concurrent invocations don't race.

### Display

- `YesNoDefault(prompt, def)` for default-Yes prompts (TOS, revoke,
  unregister).
- `Notify(msg)` for status messages.

## Phase 8 — go-certbot 1.0.0

### Implemented

- **`rollback` verb**: reverts the most recent N config-file changes
  go-certbot made (defaults to 1; configurable with `--checkpoints
  N`). Reads checkpoints from `work_dir/backups/<timestamp>-<label>/`,
  restores each file to the recorded content, removes the consumed
  checkpoint dirs, and reloads nginx/apache if their control binary
  is on PATH.
- **`internal/checkpoint` package**: simple file-snapshot mechanism.
  `Save(workDir, label, paths)` content-addresses the files under
  `backups/<timestamp>-<label>/files/<sha>` plus a `manifest.json`.
  `Restore(workDir, n)` replays the most recent N in reverse,
  consuming them. Missing files are skipped (nothing to revert to).
- **Checkpointing wired into nginx and apache** at every install /
  enhance write so `rollback` has something to undo.
- **End-to-end Pebble harness** in `tests/e2e/`. Tests start
  `pebble` + `pebble-challtestsrv` (skipping if either binary isn't
  on PATH), then exercise `cmd.Main` directly:
  - `TestE2EStandaloneIssuance` issues a cert against Pebble and
    verifies `accounts/<server>/<id>/{regr,private_key,meta}.json`,
    `live/<domain>/*.pem` symlinks, and `renewal/<domain>.conf`
    contents all match Certbot's layout.
  - `TestE2ECertificatesListsIssuedCert` follows up with the
    `certificates` verb and confirms the lineage shows up in its
    output.
  To run locally:
  ```
  go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
  go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
  go test ./tests/e2e -v
  ```

### Status

Every Certbot 5.x verb and bundled plugin now has an implementation;
go-certbot is feature-complete vs. the upstream surface area. Tagged
as **1.0.0**.

| Verb | Status |
| --- | --- |
| `run`, `certonly`, `renew`, `certificates`, `delete`, `revoke`, `register`, `unregister`, `update_account`, `show_account`, `install`, `enhance`, `rollback`, `reconfigure`, `plugins` | ✅ |

| Plugin | Status |
| --- | --- |
| `standalone`, `webroot`, `manual`, `nginx`, `apache`, 13 DNS plugins | ✅ |

The original intentional breaking changes (single static binary, no
third-party Python plugin loading, `dns-google` Application Default
Credentials fallback) remain. Smaller scope limits documented in
earlier phases (Apache `Include` resolution, per-OS overrides,
auto-creating server blocks, Augeas-level fidelity) are tracked in
GitHub issues against this repo as enhancements rather than bugs.

## Phase 7

### Implemented

- **`enhance` verb** with `--hsts` / `--uir` / `--staple-ocsp` flags.
  Applies the requested security enhancements to existing managed
  vhosts. Implemented as a new `plugins.Enhancer` interface that
  both nginx and apache satisfy:
  - HSTS: `Strict-Transport-Security: max-age=31536000` (always)
  - UIR:  `Content-Security-Policy: upgrade-insecure-requests`
  - Staple: nginx → `ssl_stapling on; ssl_stapling_verify on;`;
    apache → `SSLUseStapling on` + `SSLStaplingCache ...`.
  Idempotent on repeated runs.
- **`install` verb**: installs an existing cert into a web server
  without re-issuing. Accepts either `--cert-name` (uses the
  lineage's `live/` paths) or `--cert-path` + `--key-path`. Plugin
  picked via `--nginx` / `--apache` / `--installer`, or restored
  from the renewal conf when `--cert-name` is given.
- **`--ip-address` SANs**: lego v5's `ObtainRequest` accepts IP
  literals in `Domains` and auto-detects them via `net.ParseIP`.
  We validate the literal before sending; non-IP strings error out.
- **ACME Renewal Info (RFC 9773)** integration in `renew`. Before
  issuing, query the server's `renewalInfo` endpoint via lego's
  `Certifier.GetRenewalInfo`. If the server suggests a future
  window, defer the renewal; otherwise (or if ARI isn't supported)
  fall back to the existing `renew_before_expiry` decision.

## Phase 6

### Implemented

- **`apache` plugin** acting as both authenticator and installer.
  - Hand-rolled Apache config parser in
    `internal/plugins/apache/parser/`: tokenizer + AST + round-trip
    emitter that preserves comments, blank lines, line continuations,
    and quoted args. Line-oriented (Apache's syntax).
  - http-01 authentication: inserts a temporary
    `Alias /.well-known/acme-challenge/ <webroot>/.well-known/acme-challenge/`
    plus `<Directory>` allow block into every matching
    `<VirtualHost *:80>` (with a marker comment for clean-up).
    Serves the challenge from a scratch dir; removes the inserted
    block in `Cleanup`.
  - Install: locates `<VirtualHost>` blocks by `ServerName` /
    `ServerAlias` (exact + `*.example.com` suffix wildcard). If a
    matching `:443` vhost exists, writes `SSLEngine on` /
    `SSLCertificateFile` / `SSLCertificateKeyFile` into it. Otherwise
    clones the matching `:80` vhost as a new `:443` vhost with SSL
    directives appended. Runs `apachectl configtest` then
    `apachectl graceful`; both binaries are configurable via
    `--apache-ctl`.

### Known scope limits (planned for follow-ups)

- **`Include` / `IncludeOptional` resolution** is not implemented —
  point the plugin at the file containing the matching vhost with
  `--apache-config /path/to/file`.
- **Per-OS overrides** (Certbot's `override_centos`, `override_suse`,
  `override_alpine`, …) are not yet replicated. Phase 6 assumes the
  Debian/Ubuntu layout (`/etc/apache2/apache2.conf`) but every path
  and binary is flag-configurable, so adapting to RHEL/Alpine is a
  matter of flags rather than code.
- **Reduced Augeas fidelity**: Certbot uses python-augeas to parse
  Apache. We hand-rolled a parser. Round-tripping is byte-identical
  for simple configs, but tiny formatting differences are possible in
  complex files (preserved indentation, line-continuation rewrap).
- **`enhance` verb / HSTS / OCSP stapling / Must-Staple insertion**
  come in Phase 7.

## Phase 5

### Implemented

- **`nginx` plugin** acting as both authenticator and installer.
  - http-01 authentication: injects a temporary `location
    /.well-known/acme-challenge/` block into every matching server,
    serves the challenge from a scratch dir, reloads nginx, and
    removes the location block on cleanup.
  - Install: locates server blocks via `server_name` matching (exact
    + `*.example.com` suffix wildcard), writes
    `ssl_certificate` / `ssl_certificate_key` /
    `listen <port> ssl`, then `nginx -t` + `nginx -s reload`.
  - `--redirect` / `--no-redirect`: when set, plain-HTTP server
    blocks (listening on :80 only) get
    `return 301 https://$host$request_uri`.
- **`run` verb** (the default subcommand): picks an authenticator +
  installer from `--nginx` / `--apache` / `--authenticator` /
  `--installer` / `--configurator`, calls `obtain`, then `install`.
  Hooks pre/post/deploy + `renewal-hooks/{pre,post,deploy}/` fire at
  the same boundaries as in `certonly`.
- **Hand-rolled nginx config parser** in `internal/plugins/nginx/parser/`.
  Tokenizer + AST + emitter that round-trips real-world configs
  preserving comments and whitespace where reasonable.

### Known scope limits (documented now, planned for follow-ups)

- **`include` directives** are not yet resolved — we operate on the
  single file you point us at (default `/etc/nginx/nginx.conf`). If
  your server blocks live under `sites-enabled/*.conf`, set
  `--nginx-config /etc/nginx/sites-enabled/example.conf` for now.
- **Auto-creating a server block** when no match exists is not yet
  supported; we error out with a clear message.
- **Auto-redirect server-block creation** (Certbot will create a new
  `server { listen 80; return 301; }` if needed) is not implemented;
  Phase 5 only upgrades an existing HTTP-only server.
- **HSTS / OCSP-stapling / Auto-HSTS / Must-Staple insertion** and the
  `enhance` verb come in Phase 7.

## Phase 4

### Implemented

- All 13 DNS-01 authenticator plugins that Certbot bundles, each backed
  by the matching [lego v5](https://github.com/go-acme/lego) provider:

  | go-certbot plugin | lego provider |
  | --- | --- |
  | `dns-cloudflare`   | `cloudflare`   |
  | `dns-digitalocean` | `digitalocean` |
  | `dns-dnsimple`     | `dnsimple`     |
  | `dns-dnsmadeeasy`  | `dnsmadeeasy`  |
  | `dns-gehirn`       | `gehirn`       |
  | `dns-google`       | `gcloud`       |
  | `dns-linode`       | `linode`       |
  | `dns-luadns`       | `luadns`       |
  | `dns-nsone`        | `ns1`          |
  | `dns-ovh`          | `ovh`          |
  | `dns-rfc2136`      | `dnsupdate`    |
  | `dns-route53`      | `route53`      |
  | `dns-sakuracloud`  | `sakuracloud`  |

- For each plugin: `--dns-<name>`, `--dns-<name>-credentials`,
  `--dns-<name>-propagation-seconds` (defaults match Certbot's
  per-plugin defaults).
- Credentials file format matches Certbot's `dns_common.CredentialsConfiguration`:
  a single INI file with keys prefixed `dns_<name>_`. Permissions are
  warned if not 0600 (file is still accepted).
- Authenticator interface was refactored to support DNS-01:
  `Prepare(ctx, cfg, domains) (kind, provider, error)` replaces the
  old `PrepareHTTP01`. Standalone/webroot/manual updated to return the
  right kind. The client dispatches to `SetHTTP01Provider` or
  `SetDNS01Provider` on lego accordingly.
- `--manual` plus `--preferred-challenges=dns-01` now drives lego's
  DNS-01 path via auth/cleanup hooks — the third-party-DNS-plugin
  escape hatch described in Phase 2 is fully wired.

### `dns-google` compatibility caveat

Certbot's `dns-google` plugin requires `--dns-google-credentials` (a
service-account JSON path). Ours accepts the same flag *and* falls back
to Application Default Credentials on GCE/GKE when the flag is omitted
— a deliberate convenience improvement, but worth flagging here as a
small behavioral difference.

## Phase 3

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

Plugins not yet implemented (using them returns a clear error):

| Plugin | Planned phase |
| --- | --- |

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
