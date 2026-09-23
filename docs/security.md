# Security model

Ballast holds supply-chain trust — whoever can write to it decides what your cluster runs.
So it defaults to paranoid and says so loudly when you relax anything.

## What protects you

- **Fail-closed auth.** No users configured → exit 1, unless you explicitly set
  `"allowAnonymous": true` (read-only anonymous access; writes still need a token).
- **Salted token hashes.** `users_sha256` stores `salt:hex(sha256(salt + ":" + token))`.
  Generate with `ballast hash`. The config file should still be `0600` — hashes slow
  attackers down, they don't replace file permissions.
- **Pull-only roles.** Give CI `{"ci": "pull"}` and a leaked token can read but never
  push, delete, or poison a tag. Mutations with a `pull` token return `403` and are
  audit-logged.
- **Login rate-limit.** 10 failed attempts per minute per IP → 5-minute block (`429`).
  Successful logins reset the counter.
- **Append-only audit log.** Every push, blob push, delete, forbidden attempt, and
  auth failure lands in `auditLog` with UTC timestamp, user, and digest.
- **Frozen repos are immutable.** Anything under `<prefix>/` and any repo that has ever
  mirrored upstream rejects `PUT`/`DELETE` (`405`). Blobs still referenced by a tag
  can't be deleted (`409` — untag first).
- **Input validation everywhere.** Repository names, tags (≤128 chars), and digests
  (`^sha256:[0-9a-f]{64}$`) are validated at every handler; manifests are size-capped
  (10 MB), schema-checked (`schemaVersion: 2`), and blobs capped (2 GB). Upstream tag
  refs are path-escaped, bearer token realms must be HTTPS, and redirects never carry
  `Authorization` across hosts.

## What you must do

- **Terminate TLS in front.** Ballast speaks plain HTTP. Serving non-localhost without
  `"behindProxy": true` logs a warning on every boot. Use the compose `tls` profile
  (Caddy, automatic HTTPS) or your own proxy — BasicAuth tokens are sniffable otherwise,
  and no amount of hashing fixes a cleartext wire.
- **Keep the config and data dir tight.** `0600` on the config, non-root user (the Docker
  image already runs as uid 10001), boring firewall rules.
- **Read the audit log.** It's only useful if something watches it.

## What ballast deliberately does NOT do

No OIDC/SSO, no web login form, no session cookies, no user management UI, no UI write
actions at all. Identity federation belongs in your reverse proxy (OAuth2-proxy,
Pomerium, …), not in 2000 lines of stdlib Go. If someone asks for a "login page," point
them at this file.
