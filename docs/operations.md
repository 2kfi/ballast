# Operations

## Deploy with Compose

```bash
cp ballast.example.json ballast.json   # fill in users_sha256
docker compose up -d --build           # :5000, ./ui behind BasicAuth
DOMAIN=registry.example.com docker compose --profile tls up -d --build
```

Or raw binary: `ballast serve -config ballast.json`. From GHCR without building:

```bash
docker pull ghcr.io/2kfi/ballast:latest
```

Healthcheck: `GET /healthz` → `200 ok`, no auth required. The compose file already wires
it with `start_period: 10s`.

## Storage layout

Everything lives under `storage/` — plain files, no database:

```
<storage>/
  blobs/sha256/<hex>   # content-addressed blobs (manifests, configs, layers)
  repo/<name>/tags.json # tag -> digest pointers (+ upstream metadata)
  tmp/                 # in-flight uploads/fetches; stale (>1h) swept at boot
  audit.log            # if configured
```

**Backup:** stop the server (or accept a slightly fuzzy copy), tar the storage dir, done.
**Restore:** untar into `storage/` and boot. `tags.json` files with a `.corrupt` sibling
mean a previous crash found damage — inspect before deleting the backup.

## Garbage collection

Blobs are never deleted automatically (shared CAS: one layer may serve many tags).

```bash
ballast gc -config ballast.json           # dry-run: lists orphan blobs + MB
ballast gc -config ballast.json --apply   # delete them
```

A blob counts as referenced if a tag points at it or it appears as config/layer inside a
tagged manifest. Run GC after `rm` sprees or when disk alerts fire. There is no quota
enforcement (yet) — monitor disk like any other stateful service.

## Upgrading

Pull the new image (or binary), restart. Storage is forward-compatible plain files;
`tags.json` from older versions loads as-is. Roll back by restarting the old image —
nothing migrates, so nothing can half-migrate.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `401` on everything | wrong `--user/--token`, or `users_sha256` salt format (`salt:hex`) |
| `403` on push/delete | token has `pull` role, or `readOnly: true` |
| Refuses to start: "no users configured" | fail-closed doing its job — add users or `allowAnonymous` |
| `502 upstream: …` | upstream registry error/down; cached tags still serve from disk |
| `404` on a pull | image genuinely missing upstream (propagated, not masked) |
| `429` | rate-limit tripped — wait 5 min, check for a misconfigured prober |
| Disk full | run `gc --apply`, check `tmp/` for abandoned uploads |
| `WARNING: serving on non-localhost without behindProxy` | put TLS in front (see `security.md`) |
