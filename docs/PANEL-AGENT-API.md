# Nexounel panel — JSON agent API

The panel serves a JSON API under the **same secret web path** and the
**same session authentication** as the HTML dashboard. It is meant to
be driven by an authenticated agent session (a future agent, a script
run by the operator, or the dashboard itself). The UI and the API
share one service layer (`core/internal/panel/service.go`): every
value the API returns is the same value the dashboard renders, so the
two surfaces cannot drift apart.

Base URL in every example below: `https://<panel-host>:<panel-port><secret-path>`
where `<secret-path>` is the panel's random fixed web path (the same
path the dashboard lives under). The examples use placeholder values
only: `203.0.113.10` for a host address and `example.invalid` for
domains. Never put a real secret path, password, key, or token in a
script, log, or report.

## Authentication

1. `GET <secret-path>/login` — read the session cookie
   (`nexounel_panel_session`) from the response and the CSRF token
   from the login form's hidden `csrf_token` input. The token belongs
   to the session and stays valid for the session's lifetime; it can
   also be read from any authenticated page's hidden `csrf_token`
   inputs.
2. `POST <secret-path>/login` with the form fields `username`,
   `password`, `csrf_token` and the session cookie. A successful login
   redirects to `<secret-path>/status` and rotates the session cookie:
   keep the new cookie from that response.
3. Send the session cookie on every API request.

Rules:

- Unauthenticated API requests get **401 JSON**
  `{"error":"authentication required"}` — never a redirect, never
  data. This applies to `GET` and to mutations alike.
- `GET` API requests need authentication only; no CSRF token.
- State-changing API requests (`POST`) additionally require the
  header `X-CSRF-Token: <session CSRF token>`. A missing or wrong
  header gets **403 JSON**
  `{"error":"invalid or missing X-CSRF-Token header"}`. JSON bodies
  carry no form field, so the header is the only CSRF channel.
- Unknown `/api/*` paths get **404 JSON** `{"error":"not found"}`
  whether or not the request is authenticated.
- A wrong method on a known path gets **405 JSON** with an `Allow`
  header.
- All API responses are `application/json`. Security headers
  (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Content-Security-Policy`) are set on API responses exactly as on
  UI responses.

Example session setup (placeholders only):

```sh
PANEL="https://203.0.113.10:18081"
SECRET="<secret-path>"   # the panel's secret web path; read it from the server, never hardcode a real one here
JAR=/tmp/panel-cookies.txt

# 1. Fetch the login page, keep the cookie, extract the CSRF token.
curl -s -c "$JAR" "$PANEL/$SECRET/login" -o /tmp/login.html
CSRF=$(grep -o 'name="csrf_token" value="[^"]*"' /tmp/login.html | head -1 | sed 's/.*value="//; s/"//')

# 2. Log in (password read interactively, never stored in the script).
read -r -s -p "Panel password: " PASSWORD; echo
curl -s -b "$JAR" -c "$JAR" -X POST "$PANEL/$SECRET/login" \
  --data-urlencode "username=admin" \
  --data-urlencode "password=$PASSWORD" \
  --data-urlencode "csrf_token=$CSRF" -o /dev/null
unset PASSWORD

# 3. Call the API.
curl -s -b "$JAR" "$PANEL/$SECRET/api/status"
```

## Degraded states (read before scripting)

- **Control socket absent or dead.** The control socket is configured
  by `CONTROL_SOCKET_PATH` in the server config file; when it is empty
  (or the server config is missing/unparseable) the socket is
  *not configured*. Sessions and live registry operations then report
  `unavailable` instead of failing: API calls still return **200**
  with explicit unavailable state, and the dashboard still renders
  fully. When the socket is not configured, the `sessions`/`note`
  fields carry exactly:

  ```
  unavailable (control socket not configured — set CONTROL_SOCKET_PATH in the server config)
  ```

  When it is configured but unreachable, `control.reachable` is
  `false` and `control.error` / the note says the socket is
  unreachable. Never treat an empty `sessions` list alone as "no
  sessions": check `control.configured` / `control.available` first.
- **Registry operations are two-phase.** The registry *file* is
  written first; the control-socket command second (the ordering
  contract in `core/internal/control/control.go`). A registry
  response therefore has independent `file_written` and
  `live_applied` flags. `file_written: true, live_applied: false`
  means the change is durable but the running server has not applied
  it — restart the server (dashboard "Apply & restart server", or
  `systemctl restart nexounel` on the mother) to apply it. The
  response is still **200** in that case; check `live_applied`
  instead of assuming success from the status code. `error` names
  node IDs only, never key material.
- **Compression is symmetric-or-broken.** Dictionary compression
  (`ZSTD_DICT_ENABLED`) must match on both ends: a peer without
  dictionaries enabled drops dictionary frames. The compression
  endpoints always report `symmetric` and, on mismatch, `warning`
  with the fail-closed warning text. Treat a non-empty `warning` as
  "do not leave it like this". Enabling dictionaries through the
  panel also switches the node's negotiated compression types to
  ZSTD (1): the dictionary settings only affect zstd frames, so
  leaving the types at the LZ4 default would leave the dictionaries
  configured but inert on the wire. Disabling switches them back
  to LZ4 (2).
- **Keys are shown once.** `add` (generated key) and `rotate`
  responses include `key_shown_once` exactly once, in that response
  only. It is never retrievable again and never logged; only the key
  fingerprint is available afterwards. Copy it immediately and
  deliver it to the node. A caller-supplied `key` is never echoed
  back.
- **Mesh state is control-socket state.** `mesh.available` is false
  when the control socket is not configured or unreachable; `mesh`
  then carries `note` with the unavailable reason and an empty
  `members` list — never treat an empty `members` list alone as
  "no members": check `mesh.available` first. Member `state`
  `SUSPECT`/`DOWN` with sessions still present means heartbeats
  stopped (wedged control stream), not health. A member `last_ack`
  with an error means a config push or rotation order was received
  but not applied; no ack means it was never acknowledged — never
  assume an order took effect.
- **Pending join tokens live in panel memory only.** A panel
  restart invalidates outstanding tokens (they must be re-issued).
  Listings carry fingerprints and state only, never token values.
  A `mesh` `issue` response includes `token_shown_once` exactly
  once, in that response only — the same shown-once rule as keys.
- **Related, not part of this API.** Bootstrap enrollment itself
  runs over a separate loopback-only HTTP API (`POST /enroll`,
  no session authentication; loopback binding is its boundary)
  that the tunnel server calls. It is documented in
  `docs/PHASE3-MILESTONE-2.md` (operator notes), not here: do not
  call it from an agent session — issue and revoke tokens through
  `/api/mesh` instead.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | Liveness summary: server health, control-socket state, restart flag |
| `GET` | `/api/status` | Full dashboard state (health, nodes, resolver fleet, sessions, compression, config files, mesh, pending joins) |
| `GET` | `/api/sessions` | Live sessions via the control socket |
| `GET` | `/api/compression` | Compression status for both sides |
| `POST` | `/api/compression` | Set compression settings on both config files |
| `GET` | `/api/registry` | Registry nodes + control-socket state |
| `POST` | `/api/registry` | `reload` / `add` / `remove` / `rotate` the registry |
| `GET` | `/api/mesh` | Mesh membership table, heartbeats, and pending join tokens |
| `POST` | `/api/mesh` | `issue` / `revoke` a join token |

All paths are relative to `<secret-path>`: e.g.
`<secret-path>/api/status`.

### `GET /api/health`

Response:

```json
{
  "ok": true,
  "server": {
    "up": true,
    "details": {
      "status": "ok",
      "version": "0.2.0",
      "uptime_seconds": 99,
      "transports": {"udp_up": true, "tcp_up": true, "dot_up": false, "doh_up": false},
      "warnings": [],
      "monitoring": [{"name": "active_sessions", "value": 2, "type": "gauge", "unit": "sessions"}]
    },
    "metrics_available": true,
    "metrics_value_count": 12
  },
  "control": {"configured": false, "reachable": false, "available": false,
              "error": "unavailable (control socket not configured — set CONTROL_SOCKET_PATH in the server config)"},
  "restart_needed": false
}
```

`server.up` is false when the metrics/health endpoint cannot be
reached; `server.error` then explains why and `details` is absent.
`control` is the control-socket state (see "Degraded states").

### `GET /api/status`

The whole dashboard as JSON. Fields:

```json
{
  "server": { "...": "see /api/health server object ..." },
  "nodes": [{"id": "node-1", "fingerprint": "a1b2c3d4"}],
  "registry_error": "",
  "resolver": {
    "available": true,
    "source_file": "/opt/nexounel/logs/resolver_cache_2026-11-03.log",
    "total_resolvers": 3,
    "entries": [{"ip": "8.8.8.8", "port": 53, "domain": "example.invalid",
                 "upload_mtu": 110, "download_mtu": 1015,
                 "last_seen": "2026-11-03T06:00:00Z"}],
    "classes": [{"download_mtu": 1015, "upload_mtu": 110, "count": 3}]
  },
  "sessions": [{"session_id": 7, "node_id": "node-1", "upload_mtu": 110,
                "download_mtu": 1015, "created_at": "2026-11-03T06:00:00Z",
                "last_activity": "2026-11-03T06:01:00Z", "active_streams": 2,
                "age": "1m 5s", "last_activity_ago": "5s"}],
  "sessions_note": "",
  "throughput": {"ok": true, "up_bps": 12345, "down_bps": 1234567,
                 "up_rate": "12.1 KB/s", "down_rate": "1.2 MB/s"},
  "control": {"configured": true, "reachable": true, "available": true},
  "compression": { "...": "see /api/compression ..." },
  "config_files": {
    "server_path": "/opt/nexounel/nexounel-server.toml",
    "node_path": "/opt/nexounel/nexounel-node.toml",
    "server_present": true, "server_parseable": true,
    "node_present": true, "node_parseable": true,
    "control_socket_configured": true
  },
  "restart_needed": false,
  "mesh": { "...": "see /api/mesh mesh object ..." },
  "pending_joins": [{"node_id": "node-2", "fingerprint": "a1b2c3d4e5f60718",
                     "expires_at": "2026-11-04T06:00:00Z", "attempts": 0,
                     "used": false, "burned": false, "revoked": false}]
}
```

Notes:

- `nodes` carries key *fingerprints* only (first 8 hex characters of the SHA-256 of the key string), never key material.
- `registry_error` is present only when the registry file cannot be
  read; `nodes` is then empty.
- `resolver.available` is false when the node config is unavailable
  or no resolver cache log exists; `resolver.note` explains why and
  `entries`/`classes` are empty. Counts are never invented.
- `sessions` is always an array (empty, never `null`) when the
  socket is unavailable; `sessions_note` then holds the unavailable
  reason. `resolver.entries`/`classes` behave the same way.
- `config_files.server_error` / `node_error` appear only when a
  present file fails to parse, with the loader's message.

### `GET /api/sessions`

Response:

```json
{
  "sessions": [{"session_id": 7, "node_id": "node-1", "upload_mtu": 110,
                "download_mtu": 1015, "created_at": "2026-11-03T06:00:00Z",
                "last_activity": "2026-11-03T06:01:00Z", "active_streams": 2,
                "age": "1m 5s", "last_activity_ago": "5s"}],
  "control": {"configured": true, "reachable": true, "available": true},
  "note": ""
}
```

`note` is set (and `sessions` is empty) when the socket is not
configured or unreachable — see "Degraded states". Byte counters are
deliberately absent: this endpoint reports session membership; the
metrics endpoint owns counters. `age` / `last_activity_ago` are
relative ages ("12s", "3m 4s") computed at view time. The
Connections page (`<secret-path>/connections`, same session
authentication) shows the same sessions plus nodes, forward ports
bound, server-wide live throughput, and cumulative totals; the
`throughput` object in `/api/status` carries that live rate
(`ok: false` on the first load — a rate needs two samples — and
after a server restart, when the counters reset). Per-connection
live throughput is not exposed by the backend: the control socket
reports membership only and the metrics endpoint reports
server-wide counters, so the live rate is server-wide.

### `GET /api/compression`

Response:

```json
{
  "server": {"available": true, "dict_enabled": false, "level": 0, "long_enabled": false},
  "node": {"available": true, "dict_enabled": false, "level": 0, "long_enabled": false},
  "dictionary_version": "v1",
  "upload_dictionary_id": 1,
  "download_dictionary_id": 2,
  "comparable": true,
  "symmetric": true,
  "settings_match": true
}
```

- Each side reports the effective `ZSTD_DICT_ENABLED` /
  `ZSTD_LEVEL` / `ZSTD_LONG_ENABLED` read from its config file
  through the real config loader. When a file is missing or
  unparseable, that side is `{"available": false, "note": "… config
  unavailable"}` and `comparable` is `false`.
- `symmetric` compares dictionary enablement only. `settings_match`
  additionally requires equal levels and long-window settings.
- On a dictionary mismatch, `symmetric` is `false` and `warning`
  carries the fail-closed warning (see "Degraded states").
- `dictionary_version` / `*_dictionary_id` identify the embedded
  shared dictionaries shipped in the binaries. Both ends run the
  same binary version, so the dictionaries always match; there is
  no dictionary exchange or version negotiation.

### `POST /api/compression`

Sets compression settings in **both** config files (server and
node). Request body (all fields optional; omitted fields keep each
file's own current value):

```json
{"dict_enabled": true, "level": 9, "long_enabled": false}
```

Constraints: `level` must be 0–22 (0 keeps the legacy SpeedFastest
encoder; 9 is the measured knee). Unknown JSON fields are rejected
with 400. The request carries no compression-type fields: the node
types are derived from `dict_enabled` (1 on enable, 2 on disable),
including for partial updates that only change `level`.

Write semantics (fail-closed):

- The edit is line-based. The server file gets **only** the three
  `ZSTD_*` lines (replacing the line if the key exists, appending
  it if absent). The node file gets the three `ZSTD_*` lines **plus**
  `UPLOAD_COMPRESSION_TYPE` and `DOWNLOAD_COMPRESSION_TYPE`,
  derived from `dict_enabled`: **1 (ZSTD)** when enabling, **2
  (LZ4, the documented default)** when disabling. The type switch
  is what engages the dictionaries: the dictionary settings only
  affect zstd frames, and the presets default both negotiated types
  to LZ4, so writing the `ZSTD_*` keys alone would leave sessions
  negotiating LZ4 with the dictionaries inert. Every other byte —
  comments, ordering, unrelated keys — is preserved. The panel
  control owns all five keys on the node file as one bundle:
  applying it replaces a hand-set custom type (0/3) with the
  derived value; the previous file is preserved as `.bak` for
  recovery.
- The server config has no singular compression-type keys: it
  negotiates through `SUPPORTED_UPLOAD/DOWNLOAD_COMPRESSION_TYPES`
  lists, which default to all types. Enabling dictionaries is
  refused (422, nothing written) when the server's resolved
  `SUPPORTED_*` lists exclude ZSTD (1) in either direction,
  because the server would resolve negotiated zstd requests to
  Off and the dictionaries could not engage; add 1 to both lists
  (or remove the restriction) by hand and retry.
- Both edited files are validated by reloading them with the real
  config loaders **before either is installed**, and the previous
  file is preserved as `<config>.bak` next to it (atomic temp +
  rename, mode 0600). A bad edit never replaces a working config;
  on failure the response is **422** and neither file changes.
- If a config file contains TOML table sections and a managed key
  is absent, the edit is refused (appending would land inside the
  table and silently have no effect).

Success response (200):

```json
{
  "applied": true,
  "compression": { "...": "status after the write, see GET ..." },
  "restart_needed": true,
  "node_restart_guidance": "Restart the server from the dashboard and restart the node service on the node host to apply the new settings."
}
```

The settings take effect only after **both** processes restart:
the server (dashboard "Apply & restart server") and the node
service on the node host (the panel does not restart the node).
The response's `compression.warning` must be empty before
restarting: if it is not, the two sides still disagree.

Error cases: 400 invalid JSON / unknown field / level out of range;
422 config file missing, unparseable, or edit validation failed
(the message names the side and the reason; nothing was written).

### `GET /api/registry`

Response:

```json
{
  "nodes": [{"id": "node-1", "fingerprint": "a1b2c3d4"}],
  "control": {"configured": true, "reachable": true, "available": true}
}
```

`registry_error` appears when the registry file cannot be read.
Fingerprints only; no key material.

### `POST /api/registry`

One endpoint, `action` selects the operation. Request body:

```json
{"action": "reload" | "add" | "remove" | "rotate",
 "node_id": "node-1",
 "key": "…",        // add only, optional
 "confirm": true}   // remove only, required
```

All operations follow the ordering contract: the registry file is
written first, then the control-socket command. `reload` writes no
file. `add`/`remove`/`rotate` refuse an invalid node ID, a duplicate
ID (`add`), an unknown ID (`remove`/`rotate`), or removing the last
node, with **422** and no file change. Unknown actions and unknown
JSON fields are **400**.

Response shape (200 for every completed file operation, including
live-apply failures — see "Degraded states"):

```json
{
  "action": "rotate",
  "node_id": "node-1",
  "file_written": true,
  "live_applied": true,
  "control": {"configured": true, "reachable": true, "available": true},
  "restart_needed": false,
  "key_shown_once": "00112233445566778899aabbccddeeff",
  "key_fingerprint": "a1b2c3d4"
}
```

Per action:

- **`reload`** — asks the running server to re-read the registry
  file. `file_written` is false. With no socket configured,
  `live_applied` is false and `restart_needed` is true: restart
  the server to apply registry changes.
- **`add`** — appends the node to the registry file, then
  `add-node` on the socket. `key`: when omitted, a fresh key is
  generated and returned once as `key_shown_once` (with its
  fingerprint); when supplied, it must be a valid node key
  (16/24/32 hex characters) and is never echoed back — only its
  fingerprint is returned.
- **`remove`** — removes the node from the registry file, then
  `remove-node` on the socket. Requires `"confirm": true`. The
  remote node service is left running; removing it remotely stays
  a dashboard Nodes (SSH) operation.
- **`rotate`** — re-issues the node's key in the registry file,
  then `rotate-key` on the socket. The new key is returned once as
  `key_shown_once` (with its fingerprint). **Delivery is separate:**
  deliver the new key to the node (dashboard Nodes rotate/deliver
  over SSH) before the node can connect with it; old sessions drain
  naturally, new sessions require the new key.

`error` is present when the socket command failed after a
successful file write; `restart_needed` is then true.

### `GET /api/mesh`

The mesh membership table and pending join tokens. The `mesh`
object is the same view the dashboard renders (see "Degraded
states": check `available` before reading `members`).

```json
{
  "mesh": {
    "available": true,
    "control": {"configured": true, "reachable": true, "available": true},
    "term": "T2",
    "term_number": 2,
    "term_degraded": false,
    "version": 5,
    "chief_id": "node-1",
    "snapshot_signing": false,
    "generated_at": "2026-11-03T12:00:00Z",
    "members": [{
      "id": "node-1", "state": "ACTIVE",
      "capacity_bps": 1100, "capacity_rate": "1.1 KB/s",
      "weight": 0.6, "loss": 0.01, "loss_percent": 1,
      "leg_rtt_ms": 12, "leg_ok": true, "tenure_seq": 1,
      "last_seen": "2026-11-03T11:59:55Z", "last_seen_ago_seconds": 5,
      "active_streams": 3, "forward_ports_bound": 10,
      "config_version": 7, "stream_connected": true,
      "last_ack_for": "config"
    }]
  },
  "pending_joins": [{"node_id": "node-2", "fingerprint": "a1b2c3d4e5f60718",
                     "expires_at": "2026-11-04T06:00:00Z", "attempts": 0,
                     "used": false, "burned": false, "revoked": false}]
}
```

Notes:

- `term` renders as `T<n>`, with `(degraded)` in the dashboard
  when `term_degraded` is true (a degraded term comes from the
  last signed snapshot while the mother link is down; mother
  tables are normal terms).
- `weight` is the member's capacity share: zero means it takes no
  new streams (reserve, suspect, down, or no capacity reported
  yet). Members heard from but not yet in the enforced table
  appear with state `PENDING` and weight zero.
- `snapshot_signing` is a boolean only: it reports whether the
  mother holds a snapshot-signing key. It never carries key
  material, and no snapshot key is issued to nodes in this
  milestone (see `docs/PHASE3-MILESTONE-2.md`, D-9).
- `last_ack_for` / `last_ack_error` report the member's last
  control-stream acknowledgement: an error means a config push or
  rotation order was received but not applied. Absence means no
  ack was recorded — never assume an order took effect.
- `pending_joins` is always an array (empty, never `null`).
  `fingerprint` is the 16-character display fingerprint (a hash),
  never the token. Expired, used, and burned joins are swept on
  read, so the list never shows a dead token.

### `POST /api/mesh`

One endpoint, `action` selects the operation. Request body:

```json
{"action": "issue" | "revoke",
 "node_id": "node-2",
 "connect_address": "v.example.invalid",  // issue only, required
 "listen_port": 18000,                    // issue only, optional (default 18000)
 "forward_range": "20000-20010",          // issue only, required
 "ttl_hours": 24,                         // issue only, optional (1-24, default 24)
 "confirm": true}                         // revoke only, required
```

Unknown actions and unknown JSON fields are **400**. Validation
failures (bad node ID, connect address, port, range, or TTL) are
**400** and issue nothing. An operational failure — the derived
bootstrap key could not be pushed to the running server over the
control socket — is **422** and issues nothing: the pending join
is rolled back, so no unusable token survives.

`issue` response (200):

```json
{
  "action": "issue",
  "node_id": "node-2",
  "token_shown_once": "…43-character token…",
  "token_fingerprint": "a1b2c3d4e5f60718",
  "expires_at": "2026-11-04T06:00:00Z",
  "connect_address": "v.example.invalid",
  "listen_port": 18000,
  "forward_range": "20000-20010"
}
```

`token_shown_once` appears exactly once, in this response only:
copy it immediately and run the node in enroll mode with it. It is
single-use (one node, then it burns), bound to `node_id`, and
invalidated by a panel restart. The connect address, listen port,
and forward range are issued into the node config at enrollment;
they are the values the operator supplied here, because the
enrollment request itself carries only identity and token.

`revoke` response (200):

```json
{"action": "revoke", "node_id": "node-2", "revoked": true}
```

`revoked: false` means no pending join existed for that node
(revoking an enrolled node stays a registry removal, not this
operation). Revocation deletes the pending join and drops its
pushed bootstrap key; the token can never enroll afterwards.

## Error summary

| Status | Meaning |
|---|---|
| 400 | Invalid JSON, unknown field, unknown registry/mesh action, missing `node_id`, `remove`/`revoke` without `confirm`, level out of range (compression), invalid join-token parameters |
| 401 | No session cookie, expired/invalid session, or wrong username — authentication required |
| 403 | State-changing request without a valid `X-CSRF-Token` header |
| 404 | Unknown `/api/*` path (JSON) or unknown UI path (plain text) |
| 405 | Wrong method on a known API path |
| 422 | Registry/config operation refused or edit validation failed; no file was replaced; or a join-token bootstrap-key push failed and no token was issued |

## Security notes

- Keys, passwords, Cloudflare credentials and tokens never appear
  in API output, logs, or error messages — only key fingerprints
  and node IDs. The exceptions are the single `key_shown_once`
  value in the `add`/`rotate` response that generated it, and the
  single `token_shown_once` value in the mesh `issue` response
  that generated it.
- The API has no bearer tokens or API keys: the session cookie is
  the credential, scoped to the secret web path, `HttpOnly`, and
  idle-expiring. Treat the cookie and the CSRF token as secrets.
- Compression and registry writes are operator actions: they
  change tunnel behaviour (dictionary frames, node membership)
  and need a restart on one or both ends to take effect. The API
  reports exactly what was written, what was applied live, and
  what still needs a restart; script against those fields, not
  against assumptions.
