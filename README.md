# goreg — the boring OCI mirror

> A single-binary pull-through container registry cache. No database. No dependencies. No drama.

`goreg` sits between your machines and Docker Hub (or GHCR, Quay, …) and remembers what it
fetched — so `latest` can't rug-pull you at 3am, air-gapped clusters still install, and every
image you shipped last Tuesday is still exactly that image.

Version tags get a long memory (24h). Floating tags like `latest` get a short one (15m).
Every floating pull also freezes the concrete version it resolved to (`python:3.12` →
`goreg/python:3.12.1`) — pin your deployments to the frozen copy and upstream tag rewrites
stop being your problem.

## 60-second quickstart

```bash
# 1. build (stdlib only — go 1.26, zero dependencies)
go build -o goreg .

# 2. hash a token (never store plaintext)
./goreg hash my-secret-token
# -> 585e3c7d…:5150b87d…   (salt:hash, paste into goreg.json)

# 3. minimal config
cp goreg.example.json goreg.json   # fill in users_sha256, set storage dir

# 4. run
./goreg serve -config goreg.json
open http://localhost:5000/ui      # read-only browser (same BasicAuth token)
```

Or with Docker Compose:

```bash
cp goreg.example.json goreg.json   # fill in users_sha256
docker compose up -d --build
open http://localhost:5000/ui
```

With automatic HTTPS (recommended past localhost):

```bash
DOMAIN=registry.example.com docker compose --profile tls up -d --build
```

## What's inside

| Command | What it does |
|---|---|
| `goreg serve` | pull-through mirror + frozen snapshots + read-only WebUI |
| `goreg pull python:3.12` | prime the cache now, print the frozen tag it created |
| `goreg rm python:3.12` | untag live + frozen (blobs stay until GC) |
| `goreg gc` | dry-run orphan-blob report; `--apply` to delete |
| `goreg hash <token>` | print a `salt:hash` verifier for `users_sha256` |

Endpoints: full OCI distribution-spec (`/v2/…`), plus `/ui`, `/api/repos`, `/healthz`.

## Security model (read this before exposing it)

`goreg` holds supply-chain trust, so it defaults to paranoid:

- **Fail-closed auth** — refuses to start with no users configured unless you explicitly
  opt into `allowAnonymous`. BasicAuth tokens stored as salted SHA-256 (`users_sha256`),
  never plaintext. Per-user roles: `pull` (read-only) vs `push`/`admin`.
- **No cleartext remote** — serving non-localhost without `behindProxy:true` logs a loud
  warning. Put Caddy (included, `--profile tls`) or your own proxy in front for TLS.
- **Rate-limited logins** — 10 bad attempts/min per IP earns a 5-minute block; every
  push, delete, and auth failure lands in an append-only audit log.
- **Read-only by design** — frozen/mirror repos reject all writes and deletes; blobs
  still referenced by a tag can't be deleted; path traversal, digest spoofing, and tag
  injection are validated at every handler.

This was audited by an agent pass (35 findings, 9 critical — traversal, SSRF, open-auth,
unbounded reads, tmp leaks, tag races) and all of them are fixed. The audit notes live in
spirit in the code; the paranoia is load-bearing.

## Frozen snapshots, concretely

```
docker pull localhost:5000/python:3.12        # live mirror, revalidated on TTL
docker pull localhost:5000/goreg/python:3.12.1 # frozen: immutable, offline-safe
```

Floating tags resolve their concrete version upstream and freeze it. Deleted the frozen tag
by accident? Next revalidation restores it. Upstream rewrote `latest`? Your frozen copy
doesn't move until you re-pull.

## Config

```jsonc
{
  "addr": ":5000",
  "storage": "/data",
  "prefix": "goreg",
  "users_sha256": { "ci": "<salt:hash from `goreg hash`>" },
  "roles": { "ci": "pull" },
  "allowAnonymous": false,
  "behindProxy": true,
  "readOnly": false,
  "auditLog": "/data/audit.log",
  "ttl": { "version": "24h", "floating": "15m" }
}
```

## Layout

Six stdlib-only files, ~2000 lines, each with one job: `main.go` (CLI, `serve`/`pull`/`rm`/
`gc`/`hash`), `registry.go` (HTTP + auth + uploads), `store.go` (file CAS + tags),
`mirror.go` (TTL, revalidation, freezing), `upstream.go` (token auth, safe fetching),
`ui.go` (read-only browser). `Dockerfile`, `docker-compose.yml`, `Caddyfile` for deployment.

Boring on purpose. Boring is auditable, and auditable is trustworthy.
