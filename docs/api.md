# API & WebUI

All endpoints use HTTP BasicAuth with a configured token, except `/healthz`.

## Browser & helpers

- **`GET /ui`** — read-only WebUI: repos, tags, short digests, frozen-vs-floating badges,
  disk stats, filter box. Same BasicAuth, zero mutations, strict CSP header.
- **`GET /api/repos`** — the UI's data source, plain JSON:
  `{"repos": [{"name": "python", "tags": [{"tag": "3.12", "digest": "sha256:…",
  "frozen": true, "age": "2h0m0s"}]}], "stats": "… 4 repos · 120 blobs · 1 GB"}`.
- **`GET /healthz`** — `200 ok`, unauthenticated. Use it for container probes.

## Registry endpoints (OCI distribution-spec)

| Method | Path | Notes |
|---|---|---|
| `GET/HEAD` | `/v2/` | auth ping → `{}` |
| `GET/HEAD` | `/v2/<name>/manifests/<tag\|digest>` | live tags revalidate on TTL; frozen namespace serves disk-only |
| `PUT` | `/v2/<name>/manifests/<tag>` | client push; JSON ≤10 MB, `schemaVersion: 2`; blocked on mirror/frozen repos |
| `DELETE` | `/v2/<name>/manifests/<tag\|digest>` | untag only; blocked on mirror/frozen repos |
| `GET/HEAD` | `/v2/<name>/blobs/<digest>` | lazy upstream pass-through on cache miss (GET only) |
| `DELETE` | `/v2/<name>/blobs/<digest>` | `409` while any tag references it |
| `GET` | `/v2/<name>/tags/list` | `{"name":…, "tags":[…]}` |
| `POST` | `/v2/<name>/blobs/uploads/` | start upload (`?mount=<digest>` fast-path); returns `Location` + `Docker-Upload-UUID` |
| `PATCH` | `/v2/<name>/blobs/uploads/<id>` | chunk; returns cumulative `Range` |
| `PUT` | `/v2/<name>/blobs/uploads/<id>?digest=…` | finish; digest-verified into CAS |

Wrong methods get `405`; bad names/tags/digests get `400`. Upstream 404s propagate as
`404` (not masked as `502`) so clients can tell "missing" from "upstream down".
