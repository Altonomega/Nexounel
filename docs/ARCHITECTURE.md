# Nexounel Architecture Plan

Status: approved direction, 2026-11-01. Research phase complete.
Core base: CottenDNS @ `7db7b73` (2026-10-24), LICENSE verified MIT
verbatim (attribution preamble + full MIT text; GitHub's NOASSERTION is a
detector quirk). Base commit pinned here; re-verify the tree before any
code is copied.

## 0. Goal

A DNS-based tunnel between two servers — one in Iran, one outside
("mother") — that stays usable when ordinary paths are blocked or
degraded. It is an **emergency-grade path**, not a VPN replacement and
not invisible: high-entropy unique subdomains under one apex are
observable by design. Success means: stable, self-healing, measurable
throughput on the real Iran↔abroad path, with setup an admin can finish
from a web panel.

Non-goals for v1: general-purpose user VPN apps, mobile clients,
invisibility against a capable observer, throughput claims without
field measurement.

## 1. What the research established

Research notes: `research` was conducted in four tracks (MasterDnsVPN,
StormDNS, WhiteDNS/CottenDNS, resolver behavior). Findings that
constrain this design:

1. **Lineage, not peers.** MasterDnsVPN (Go, MIT, active Oct 2026)
   → StormDNS (fork, dormant since May 2026) → CottenDNS (most
   advanced, active Oct 2026). CottenDNS already implements the spirit
   of per-resolver adaptation: empirical probing, throughput-optimal
   clustering, reserves, MTU-weighted balancing, record-type rotation,
   Reed–Solomon FEC, ARQ, per-resolver AIMD pacing, DoT/DoH/TCP
   carriers.
2. **Capacity cannot be asked; it must be probed.** DNS has no
   mechanism by which a resolver advertises transfer capacity, MTU, or
   rate limits. The only volunteered number is the EDNS OPT advertised
   UDP buffer (commonly 1232 or 4096) — a receive claim, not a
   forwarding guarantee. CHAOS queries (`version.bind`, `hostname.bind`)
   and NSID reveal identity only. Effective capacity is measured
   behaviorally: graduated-size answers from our own authoritative
   server, observed intact / truncated / failed, per resolver, per
   anycast instance (NSID-pinned), per record type.
3. **MTU is session-global in all three cores.** One `SESSION_INIT`
   fixes one upload and one download MTU for the whole session. True
   per-resolver sizing requires multiple sessions or renegotiation.
   MasterDnsVPN additionally collapses probed capacities to one
   "synced" MTU and discards sub-minimum resolvers — the exact waste
   this project removes.
4. **Rate limits, not payload size, are the binding ceiling.**
   Published/measured per-IP walls: Google ~500 q/s slip, ~1500 q/s
   hard wall; Cloudflare ~1000 q/s measured, unpublished; Quad9 and
   OpenDNS unpublished (assume ≤100 q/s until measured). Duplication
   multiplies volume against each resolver's budget and the
   authoritative server's load. Design response: per-resolver rate
   caps + pacing + deduplication, never unbounded duplication.
5. **Protocol facts.** Upstream payload rides QNAME labels (≤63
   octets/label, ≤253/255 octets/name). Downstream rides answer
   records; TXT is the most portable carrier, NULL the most efficient
   where it passes, CNAME/HTTPS/SVCB/A/AAAA are rotations/fallbacks.
   Unique QNAME per query + TTL 0 defeats caching. Fragmentation
   above ~1232–1400 bytes is the practical downstream ceiling
   regardless of advertised buffers. Each query is an independent
   recursive resolution; only the authoritative server holds state —
   there is no hop-by-hop handoff.
6. **Shared weaknesses to fix, not inherit.** All three cores use one
   static shared key for all clients, accept unauthenticated legacy
   ciphers (XOR/ChaCha20) by default, have no web panel, no Cloudflare
   automation, no server-to-server mode, and GitHub-only installers.
   None publishes real-network throughput.

## 2. Core innovation: per-class multi-session sizing

The design that turns the probing result into the user's idea:

1. **Probe.** On session start (and on failure, and periodically),
   for each resolver × record-type × NSID-identified instance:
   identity (CHAOS + NSID, 2–4 queries), downstream ladder
   (768 → 1152 → 1344 → 1440 → 1488 → 1512 → 1524 + binary
   refinement, ~7–12 queries), upstream length probe (~5–8 queries),
   optional rate ramp. Classify outcomes: intact / TC-truncated
   (counts as UDP failure) / SERVFAIL / timeout. Cost ≈ 25–40
   queries per resolver per record type, one-time; re-probes ≈ 10–15.
2. **Operate at measured capacity minus 5%.** The operating size for
   a class is `0.95 × largest repeatedly-intact UDP size`. The 5%
   margin absorbs drift, anycast variance, and fragmentation
   differences between vantage points.
3. **Cluster into MTU classes.** Group resolvers by measured
   `(upload, download)` capacity. Retain CottenDNS's
   throughput-optimal score per class —
   `score(U, D) = (U + D) × (resolvers with upload ≥ U and download ≥ D)`
   — and its reserve/hysteresis rules (>12.5% improvement required to
   move the operating point).
4. **One session per class.** Each class runs its own session with
   its own negotiated MTU. A multiplexer above the sessions stripes
   streams across classes (weighted by measured capacity, loss, and
   latency) and re-stripes on class failure without dropping streams
   held by surviving classes. Resolvers below a class floor are
   reserves, never discarded.
5. **Continuous adaptation.** Re-probe on truncation/timeout events
   and on a slow cadence; demote/promote classes with hysteresis;
   never renegotiate a live session's MTU mid-stream — replace the
   session, drain, and move streams.

This keeps every resolver working at its own measured capacity,
removes the single-synced-MTU waste, and bounds probe cost to a few
dozen queries per resolver.

## 3. Components

```
nexounel-server   authoritative DNS endpoint on the mother server (UDP/TCP 53),
                  derived from CottenDNS udpserver + dnsparser + vpnproto.
nexounel-node     Iran-side client: DNS carrier + TCP forwarder for a
                  configured port range + local health/metrics endpoint.
nexounel-panel    web UI on the mother server: setup wizard, node
                  provisioning, status, key management.
nexounel-install  mirror-aware installer (mother + node), NexoShield-style
                  flat one-line install.
core lib          carrier / ARQ / FEC / security / basecodec, surgically
                  derived from CottenDNS internal/ packages (see §7).
```

### 3.1 Server (mother side)

- Listens UDP/TCP 53 as authoritative nameserver for the delegated
  tunnel subdomain. Delegation: `ns.example.com A <mother IP>` (DNS-only)
  + `v.example.com NS ns.example.com` (never CDN-proxied).
- Answers with the queried record type, TTL 0. NXDOMAIN for
  non-tunnel queries (keeps the namespace clean; still fingerprintable
  as a tunnel endpoint — accepted, see §0).
- Per-class session store, stream multiplexing, ARQ + FEC (retained
  from CottenDNS), flood/abuse ceilings (bounded queues, session/stream
  caps, per-instance budgets).
- Egress: direct dial, upstream SOCKS5, or fixed TCP target per
  forwarded port.

### 3.2 Node (Iran side)

- Runs as a service on each Iran server. No inbound ports required:
  it dials out through resolvers to the mother, like the user apps of
  the reference projects — but headless, configured, and managed.
- Forwards a configured TCP port range (e.g. 10001–10010) from the
  Iran server's public side to the mother's localhost equivalents
  (same port mapping model as the WaterWall reverse tunnels: user
  connects to Iran:1000X, traffic emerges on the mother).
- Local-only health/metrics endpoint (never publicly exposed).
- Reconnects, re-probes, and re-establishes sessions autonomously;
  survives resolver death, mother restart, and path changes.

### 3.3 Panel (mother side)

- Served only under one random, fixed webpath (e.g.
  `/jlkfjklfajkmAlkdjeskjf`), generated at install time and printed
  once in the terminal. Every other path returns 404. No information
  about the panel leaks from 404 responses.
- Username + password login (argon2/bcrypt-hashed, stored server-side
  only), session cookie with secure flags, login rate limiting and
  lockout. Both layers (secret path + login) are required; neither
  alone is trusted.
- Setup wizard (first login): two paths, both ending with the same
  deliverables — connect address + encryption key material:
  - **Manual:** guided Cloudflare record creation (exact records,
    values, and verification checks; the panel verifies delegation
    with live DNS lookups before proceeding).
  - **Automatic:** admin supplies a Cloudflare Global API key; the
    panel calls Cloudflare API v4 (list zones → create `A` + `NS`
    records), verifies delegation, and reports success/failure per
    record. The key is used once for setup and is never stored in
    plaintext (kept only as needed for record management, encrypted
    at rest; revocation guidance shown).
- Node provisioning: admin enters an Iran server's IP, SSH port, and
  SSH credentials in the panel. The mother provisions the node over
  SSH: installs the node binary + config (port range, mother address,
  per-node key), starts the service, verifies the tunnel, and reports
  status. SSH access uses an ephemeral keypair generated for the
  provisioning run and deleted afterwards (temporary access never
  persists); password auth is supported but key-based is preferred.
- Runtime views: tunnel status per node, per-class resolver health,
  measured throughput/latency/loss, QPS budget usage, logs (bounded
  retention), key rotation, node add/remove.

### 3.4 Installer

- One flat command, NexoShield-style. Idempotent, resumable, with
  predicted errors handled automatically where possible and a clear
  failure message otherwise.
- **Mirror strategy (hard requirement).** All downloads (Go toolchain
  if building from source, release artifacts, OS packages) resolve
  through a mirror list: Iranian mirrors + foreign mirrors + GitHub.
  The installer times each mirror (short HEAD/fetch probe) and uses
  the fastest that serves the artifact, falling back to the next on
  any failure. No single-mirror dependency. `curl | sudo bash` from
  one personal account is explicitly rejected as a pattern: artifacts
  are checksum-verified (SHA-256 pinned in the installer) before use.
- Go 1.26+ toolchain bootstrap when building from source (Debian 12
  ships older Go; the installer fetches the toolchain from the
  fastest mirror, verifies its checksum, and caches it).
- Systemd units, firewall rules (UDP/TCP 53 on the mother; nothing
  inbound on nodes), log rotation, uninstall path.

## 4. Security model (fixes the inherited weaknesses)

- **Per-node keys.** No single shared key. Each node gets its own
  key, issued by the panel at provisioning; compromise of one node
  does not compromise the mother or other nodes. Keys are rotatable
  from the panel; rotation re-issues and restarts only the affected
  node.
- **Authenticated encryption only.** AES-256-GCM (method 5
  equivalent). Cipher auto-detection OFF; legacy unauthenticated
  codecs (XOR, unauthenticated ChaCha20, plaintext) are removed from
  the build, not merely disabled by config.
- **No secrets in the repo, logs, or team docs.** Keys, API tokens,
  and passwords live only in root-only server files (0600) and the
  panel's encrypted store. The same discipline as the WaterWall
  deployments: secrets are never printed, logged, or committed.
- **Panel hardening.** Secret path + login + rate limiting; no
  panel surface on any other path; local-only metrics; security
  headers; no version disclosure in error pages.
- **Transport honesty.** DoT/DoH protect only the client→resolver hop;
  the resolver→mother hop remains plaintext DNS. This is stated in
  the docs, not hidden. Record-type rotation and QNAME shaping reduce
  fingerprinting but do not eliminate observability.

## 5. Multi-Iran phase (Phase 3, design-open)

Phase 1 is one Iran server + mother. The multi-Iran idea is kept
deliberately open until Phase 1 is measured, with two candidate
topologies to evaluate then:

- **(a) Chief aggregator.** The first Iran server ("chief") receives
  sibling credentials from the panel, provisions siblings itself,
  stripes user streams across sibling uplinks through its own
  multiplexer, and presents a single entry point to users. The chief
  is a single point of failure; mitigation is panel-driven
  re-election (promote a sibling to chief) — design and failure
  semantics to be specified in Phase 3.
- **(b) Xray mesh.** Use the Xray core for inter-Iran networking
  (routing, balancing, failover between Iran nodes) with the DNS
  carrier as one transport among others. Xray is proven on the
  operator's existing tunnels; its role here is orchestration, not
  transport replacement.

Decision rule: build (a)'s provisioning path only after Phase 1
numbers exist; evaluate (b) against the same measured baseline. No
commitment to either until then. The vague "chief distributes
requests" idea is expanded here into a concrete requirement: the
distribution unit is the *stream*, the striping policy is
capacity/loss/latency-weighted, and the user-visible entry point
never changes when siblings join or leave.

## 6. Phases and acceptance criteria

- **Phase 0 — Research. DONE (2026-11-01).** Four tracks, core
  selected, LICENSE verified, this plan published.
- **Phase 1 — Core surgery + single tunnel.** Fork/derive the
  CottenDNS core into `core/`; remove legacy ciphers; implement
  per-class multi-session sizing (§2) behind the existing session
  machinery; build `nexounel-server` + `nexounel-node` with port-range
  forwarding. Acceptance: loopback bench passes; lab DNS test
  (local authoritative + resolver) transfers byte-exact data both
  ways; field test mother↔Iran measures throughput up/down, RTT,
  loss, QPS, and 24h stability against the CottenDNS baseline.
- **Phase 2 — Panel + provisioning.** Panel with secret path + login,
  setup wizard (manual + Cloudflare-auto), SSH provisioning of one
  Iran node, status views, key rotation. Acceptance: full install →
  wizard → provisioned tunnel with zero manual server commands after
  the one-line install.
- **Phase 3 — Multi-Iran.** Chief model and/or Xray mesh per §5.
  Acceptance: two Iran nodes behind one entry point, measured
  aggregate vs single-node, chief-failure behavior documented.
- **Phase 4 — Hardening + release.** Installer mirror matrix tested
  from Iran and abroad, uninstall path tested, docs (operator guide +
  team guide, secret-free), versioned release, field measurement
  report published in-repo.

## 7. Surgery scope (what changes in the derived core)

Retain: `dnsparser` (wire format), `vpnproto` (framing), `arq`
(reliability), `fec`, `basecodec`, `compression`, `resolvertransport`
(carriers + pacing), `udpserver` (ingress), `config` (TOML).
Remove: legacy cipher methods 0/1/2 and auto-detection, CottenMax
beta engine (re-evaluate in Phase 3), client UI/TUI code, Android
integration docs. Add: per-class session manager + multiplexer (§2),
per-node key handling, panel API surface, node provisioning agent,
mirror-aware installer. Every retained file keeps its upstream
copyright notice; new files are MIT under Mashani.

## 8. Risks and open questions

- Detection/observability: tunnel-shaped DNS volume is the canonical
  signature; mitigation is rotation/shaping, not invisibility.
- Rate-limit drift: resolver policies change by jurisdiction and
  over time (e.g. Quad9/France, Nov 2026); the pacer + re-probing
  must absorb it, and the resolver list must stay operator-editable.
- Anycast variance: one IP, many instances; NSID pinning + medians
  required, single-probe results are not trusted.
- Fragmentation: path MTU differs by vantage point; the 5% margin
  and the 1232–1400 practical ceiling bound this.
- Go toolchain on old distributions; Cloudflare API scope/rotation
  UX; panel credential recovery if the admin loses the webpath
  (recovery = re-run of a local CLI on the mother, never email).
- Field speed is unproven for every core in this family on the
  target networks; no architecture commitment in Phases 2–3 is final
  until Phase 1 field numbers exist.

## 9. Repository layout (planned)

```
cmd/server/ cmd/node/ cmd/panel/   entry points
core/                               derived tunnel core (see §7)
panel/                              web UI + API + wizard + Cloudflare client
install/                            installer + mirror lists + systemd units
docs/                               ARCHITECTURE.md, OPERATOR-GUIDE.md (later)
tests/                             unit + lab integration tests
```

## 10. Credits

Tunnel lineage: MasterDnsVPN (Amin Mahmoudi) → StormDNS (NullRoute1970)
→ CottenDNS (tajirax), MIT. Nexounel is an independent derivative by
Mashani (MNSH-Nexo). Research reports that produced this plan are kept
outside this repository.
