# Configuration

Ballast reads one JSON file (`-config`, default `ballast.json`). Unknown fields are
ignored; invalid values fail fast at startup — a bad config never boots half-working.

```jsonc
{
  "addr": ":5000",                    // listen address
  "storage": "/data",                 // data dir (blobs, repos, tmp, audit log)
  "prefix": "ballast",                // frozen namespace: <prefix>/<repo>:<concrete>
  "users_sha256": {                   // user -> "salt:hex(sha256(salt:token))", see below
    "ci": "a9e6a0e56:…"
  },
  "roles": { "ci": "pull" },          // pull | push | admin (default: admin)
  "allowAnonymous": false,            // anonymous GET/HEAD only; default false
  "behindProxy": true,                // set when TLS terminates at a reverse proxy
  "readOnly": false,                  // refuse all PUT/DELETE/PATCH/POST when true
  "auditLog": "/data/audit.log",      // append-only audit log ("" disables)
  "upstreams": {                      // per-host upstream creds / base override
    "registry.example.com": { "username": "u", "password": "p" }
  },
  "ttl": { "version": "24h", "floating": "15m" },
  "defaultPlatform": "linux/amd64"    // which arch to prefetch from multi-arch indexes
}
```

Legacy `users` (`user -> plaintext token`) still works but logs a warning on every boot.
Migrate with:

```bash
ballast hash my-secret-token   # prints salt:hex — paste into users_sha256
```

## Field notes

- **Fail-closed.** No `users`/`users_sha256` and no `allowAnonymous:true` → refuse to
  start. There is no silent open mode.
- **Roles.** `pull` can GET/HEAD only (registry reads, `/ui`, `/api/repos`). `push` and
  `admin` are currently equivalent (full write); the split exists so CI tokens can be
  least-privilege from day one.
- **`allowAnonymous`.** Anonymous clients may only read (`GET`/`HEAD` on `/v2/…`, `/ui`,
  `/api/repos`). Any mutation still needs a token. `/healthz` is always unauthenticated.
- **`prefix`** must match `^[a-z0-9]+([._-][a-z0-9]+)*$` — it becomes part of repository
  names (`ballast/python:3.12.1`), so slashes and `..` are rejected.
- **TTL strings** must parse as Go durations (`24h`, `15m`, `30s`). Typos fail at startup
  instead of silently falling back.
- **`defaultPlatform`** picks which manifest to prefetch from multi-arch indexes
  (`os/arch`, e.g. `linux/arm64` for a Pi cluster). Other arches fill in lazily on pull.
