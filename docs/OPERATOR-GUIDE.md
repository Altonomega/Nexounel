# Nexounel Operator Guide

How to install, set up, and run Nexounel: a DNS-based tunnel between a
mother server (outside the restricted network) and one or more node
servers (inside it). This guide covers the Phase 2 deliverables: the
installer, the web panel, the setup wizard, SSH provisioning, key
rotation, and uninstall. For the design and the research behind it, see
[`ARCHITECTURE.md`](ARCHITECTURE.md).

No step in this guide requires pasting a password, key, or token into a
chat log, ticket, or shared document. Secrets live only in root-only
files on the servers themselves (mode `0600`) and are never printed.

## 1. Concepts

- **Mother**: the server that answers DNS queries for the tunnel
  subdomain (for example `v.example.invalid`). It runs
  `nexounel-server` on UDP/TCP port 53 and the web panel.
- **Node**: a server inside the restricted network. It runs
  `nexounel-node`, accepts local TCP connections on a configured
  forward range, and carries them to the mother through public DNS
  resolvers.
- **Panel**: the web UI on the mother. It is reachable only under one
  random, fixed web path (for example
  `http://<mother>:18081/<32-random-chars>`), plus a username/password
  login. Every other path returns a generic 404. Both layers are
  required; neither alone is trusted.
- **Registry**: `/opt/nexounel/nodes.toml` on the mother. One entry
  per node: an id and its own key (inline, or a `key_file`). Keys are
  never logged; only the first 8 hex characters of the key's SHA-256
  (the fingerprint) ever appear in logs or the panel.
- **Capacity classes**: the node probes each resolver's upload/download
  capacity and groups resolvers into classes. Each class runs its own
  session, sized at 95% of the probed capacity. There is no single
  fixed MTU for all resolvers.

## 2. Install

The installer is a single script. Download it, inspect it, then run it
as a file. Never pipe it to a shell (`curl | sudo bash` is rejected by
design: artifacts are checksum-verified before use).

```sh
# Inspect first, then run. Replace <version> with the release you want.
curl -fLO https://github.com/Altonomega/Nexounel/releases/download/<version>/install.sh
less install.sh
sudo bash install.sh --mother    # mother server: server + panel
sudo bash install.sh --node      # node server: node only
sudo bash install.sh --mother --node   # both roles on one host (lab use)
```

Useful flags: `--dry-run` (print every action, change nothing),
`--non-interactive` (skip prompts; the panel is left uninitialized),
`--help` (works offline), `--uninstall`, `--version`,
`--tarball <path> --sha256 <hash>` (install from a local release
tarball), `--mirror <url>` (repeatable; see §2.1), `--destdir <dir>`
(testing only: install into a scratch root, no system changes).

The installer is idempotent and resumable: re-running it upgrades the
binaries and preserves existing configs, keys, the registry, and panel
credentials (backups are kept with a `.bak-<date>` suffix and never
deleted by the installer). It runs `-check-config` equivalents before
starting services and refuses to start a service whose config is
invalid.

### 2.1 Mirrors and verification

Every download (release tarball, Go toolchain for source builds, OS
packages) resolves through a mirror list: the installer probes each
mirror with a short HEAD request, uses the fastest that serves the
artifact, and falls back to the next on any failure. The default list
covers GitHub release hosting; add your own mirrors with `--mirror`
(repeatable) or the `NEXOUNEL_MIRRORS` environment variable
(comma-separated base URLs) — for example an Iranian mirror of GitHub
releases if direct access is slow from your network. Every release
tarball is SHA-256-verified against the `.sha256` file fetched from the
same mirror before extraction; a mismatch aborts the install.

Building from source (`--build-from-source`) additionally requires
`--go-sha256` and `--source-sha256` (fail-closed: the installer never
runs unverified code). The Go toolchain is cached under
`/opt/nexounel/.build` (or `~/.cache/nexounel` when unprivileged).

### 2.2 What gets installed

| Path | Contents |
|---|---|
| `/opt/nexounel/` | Binaries (`0755`), configs (`0600`), `nodes.toml`, panel config |
| `/etc/systemd/system/nexounel*.service` | `nexounel`, `nexounel-node`, `nexounel-panel` units |
| `/etc/logrotate.d/nexounel` | 7-day rotation for `/var/log/nexounel/*.log` |
| `/var/log/nexounel/` | Log directory |

Units run as `User=root`, `WorkingDirectory=/opt/nexounel`,
`Restart=on-failure`. The installer prints firewall notes but applies
no firewall rules: the mother needs inbound UDP **and** TCP on port 53;
nodes need nothing inbound.

### 2.3 Port 53 bind lesson

On the mother, bind a **specific IP** in `nexounel-server.toml`
(`UDP_HOST`), not `0.0.0.0`. `systemd-resolved` owns the loopback
stubs on `:53` (127.0.0.53/127.0.0.54) and a wildcard bind conflicts
with them: the server fails with `address already in use`. Use the
host's public (or stable private, behind NAT) address. The sample
config ships `UDP_HOST = "0.0.0.0"`; change it before starting the
server in production. Registry and key paths in the server config must
be absolute.

### 2.4 Panel first-run init

On `--mother` installs the installer prompts for the panel admin
password (twice, no echo, minimum 12 characters), then runs
`nexounel-panel -init`, which writes
`/opt/nexounel/nexounel-panel.toml` (`0600`) containing the hashed
password, a freshly generated 32-character secret web path, and a
session key. It then runs `-check-config` and prints the panel URL
once. **Save the URL** — the web path is the first layer of panel
secrecy. With `--non-interactive`, no credentials are written; run
`nexounel-panel -init` manually on the mother afterwards, then
`nexounel-panel -check-config` and
`systemctl enable --now nexounel-panel.service`.

If you lose the web path or the password, recovery is a local CLI
re-run on the mother — never email, never a reset link:
`nexounel-panel -init -force` (re-generates the web path and
credentials; the old ones stop working).

## 3. Setup wizard (first login)

Log in at the panel URL. The wizard offers two paths with the same
deliverables: the tunnel connect address and node key material, shown
**once** (copy them immediately; a re-issue path exists via rotation,
§5).

### 3.1 Manual path

1. Enter the domain (for example `example.invalid`), the tunnel
   subdomain (default `v`), and the mother's public IP.
2. The panel shows the exact records to create at your DNS provider
   (Cloudflare or any provider), DNS-only (never CDN-proxied):
   - `A ns1.<domain> → <mother IP>`, TTL 300, DNS-only.
   - `NS <subdomain>.<domain> → ns1.<domain>`, TTL 300.
3. Create the records, then let the panel **verify** them: it issues
   live DNS lookups against the explicit public resolvers 8.8.8.8 and
   1.1.1.1 and shows per-record, per-resolver status. A record passes
   when at least one of the two resolvers confirms it. The wizard
   proceeds only after verification.
4. Confirm to write the first registry entry and receive the node key
   material.

The panel never deletes or modifies existing DNS records. In manual
mode it creates nothing at all — it only reads.

### 3.2 Automatic path (Cloudflare)

1. Enter the domain, subdomain, and mother IP as above.
2. Paste a Cloudflare credential: either a Global API key (with the
   account email) or a scoped API token. Both auth styles are
   supported.
3. The panel calls Cloudflare API v4: list zones → create the two
   records → verify (same DNS checks as the manual path), showing
   per-record status.
4. The credential is used **transiently for that wizard run only**. It
   is never written to disk, logs, or config — not as plaintext, not
   as ciphertext. It is absent after the run. Any later record
   management requires re-entering it.
5. After success the panel shows revocation guidance: revoke/rotate
   the Global API key you pasted, and for any future record
   management use a scoped API token limited to Zone:DNS:Edit on the
   single zone.

Hard rule, enforced in the code: the Cloudflare client can only list,
create, and verify. It has no delete or update capability, and a test
asserts that no such method exists.

## 4. Provisioning a node (panel → node over SSH)

In the panel, open Nodes → Add node. Enter the node's IP, SSH port,
and credentials (password auth supported; key-based preferred). The
flow, with per-step status in the panel job log (credentials redacted):

1. **Connect** over SSH (x/crypto/ssh). Host-key check is TOFU with
   explicit admin confirmation: the first connection shows the
   SHA-256 fingerprint and waits for your confirmation. A changed
   fingerprint on a later run is rejected, never blindly accepted.
   Confirmed fingerprints are stored in the panel config.
2. An **ephemeral** ed25519 keypair is generated in memory for this
   run only. Its public key is appended to the target's
   `~/.ssh/authorized_keys` over the password session; the panel then
   reconnects with it.
3. The panel transfers the node binary (the mother's local release
   copy; its version is recorded and a mismatch is warned), the
   generated node config, the node key file (`0600`), and the
   resolvers file.
4. Remote install: `mkdir -p /opt/nexounel`, `install -m 755/600`,
   the `nexounel-node.service` unit (same shape as §2.2),
   `daemon-reload`, `enable --now`, then verification
   (`systemctl is-active` + forward-range listen check).
5. **Always afterwards**, the ephemeral key is removed from
   `authorized_keys` (finally-block) and removal is verified by
   re-listing the file. Temporary access never persists.
6. On any failure, transferred key material is removed from the
   target, pre-existing services are left untouched, and the failing
   step is reported plainly. Every step has a timeout.

Targets must be Debian/Ubuntu with systemd; anything else is detected
and refused with a clear message. The node config the panel writes
uses absolute paths and the forward range, listen address, and
resolver list you confirm in the form (defaults: listen `0.0.0.0`,
port `18000`, multi-session on, 0.95 capacity margin).

## 5. Status views, rotation, removal

- **Status**: server up/down via the server's `-metrics-address`
  endpoint (scrape of `/healthz` + `/healthz/details`, best-effort;
  shows "unavailable" rather than fabricated numbers when the
  endpoint is absent — start the server with `-metrics-address
  127.0.0.1:9090` to enable it). Nodes list id + key fingerprint
  only. Per-class resolver health and measured MTUs come from the
  node's config and its last probe log when the panel runs on the
  same host as a node; on the normal mother/node split they honestly
  report "unavailable" — no node API is invented. Log tails are
  bounded (last N lines of both units) and redacted: any line
  mentioning a key, password, secret, or token is dropped, never
  rendered.
- **Key rotation**: Nodes → Rotate re-issues one node's key, updates
  the registry (atomic write, validated before it takes effect),
  delivers the new key file via a provisioning run, restarts only
  that node, and verifies it. If delivery fails after the registry
  was updated, use "Re-deliver the current key" (delivers the
  registry's current key without rotating again). Rotation never
  touches other nodes or the server config — but the server reads
  the registry at startup, so after any registry change the panel
  shows a "restart needed" banner with an admin-confirmed "Apply &
  restart server" button (local `systemctl restart nexounel` +
  verification; when `systemctl` is unavailable it shows the manual
  command instead).
- **Node removal**: deletes the registry entry. With the explicit
  confirmation checkbox, it also stops/removes the remote node
  service and key file (the binary is left in place). Removal never
  touches other nodes.

## 6. Uninstall

```sh
sudo bash install.sh --uninstall
```

Stops and disables the units, removes binaries, units, and the
logrotate file. It asks (default: no) before deleting configs that
hold keys (`nodes.toml`, `*.key`, `nexounel-panel.toml`, server/node
configs); with `--non-interactive` it preserves them and says so.
Nothing outside `/opt/nexounel`, its units, and the logrotate file is
ever deleted. Backups (`.bak-<date>`) and logs are left in place.

## 7. Troubleshooting

- **Server fails with `address already in use` on :53**: see §2.3 —
  bind a specific IP; check `ss -tlnup | grep :53` for the
  `systemd-resolved` loopback stubs.
- **Panel refuses to start / "run -init"**: no credentials are
  configured. Run `nexounel-panel -init` on the mother. If the port
  is occupied, the panel fails fast with a clear message — pick a
  free `listen_addr` in the panel config.
- **Login lockout**: 5 failed logins lock that (IP + username) for 5
  minutes. Wait, or restart the panel (lockout state is in-memory).
- **Wizard verification fails**: DNS propagation takes time (TTL 300
  on the delegation records is typical). Check the records are
  DNS-only at the provider, then re-run verification from the
  wizard. The panel shows which resolver answered what.
- **Provisioning fails at host-key confirmation**: the fingerprint
  shown must match the target's real host key (compare via an
  independent channel). Never confirm a fingerprint you did not
  verify.
- **Provisioning fails at OS detection**: the target must be
  Debian/Ubuntu with systemd. Other systems are refused by design.
- **Status shows "unavailable" for metrics**: start the server with
  `-metrics-address 127.0.0.1:9090` (or set `metrics_addr` in the
  panel config to the address the server uses). The panel never
  invents numbers.
- **Resolver health "unavailable"**: expected when the panel runs on
  the mother and the node runs elsewhere. It reflects local probe
  logs only.
- **Field-test honesty**: never test tunnel connectivity with raw
  sockets from a sandboxed/proxied host — egress proxies can
  complete TCP handshakes locally and park the connection, which
  looks exactly like a blackholed service, and they throttle long
  downloads. Run connectivity and throughput tests from a host with
  direct egress (for example, from the mother server itself over
  SSH), or with proxy-aware tools (`curl`). Measure throughput from
  the mother, not from behind a proxy.

## 8. Transport honesty

DoT/DoH and record-type rotation protect only the client→resolver
hop and reduce fingerprinting; the resolver→mother hop remains
plaintext DNS. Tunnel-shaped DNS volume is observable by design;
rotation, shaping, and per-resolver sizing reduce the signature but
do not eliminate observability. This is stated, not hidden.

## 9. Building a release (operators)

`install/package-release.sh` builds the three binaries from the repo
(`-trimpath`, version stamped via `-ldflags`), assembles a
deterministic tarball + `.sha256`, and verifies it (re-extract, list,
`sha256sum -c`, each binary's `-version`):

```sh
./install/package-release.sh --version 0.2.0 --out /tmp/releases
```

Version precedence: `--version` flag → `git describe --tags --always`
→ `VERSION` file → `dev`.
