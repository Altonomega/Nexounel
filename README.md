# Nexounel

A DNS-based tunnel between two servers (one inside Iran, one outside),
built for emergency-grade stability when ordinary paths are blocked or
degraded. It carries TCP streams inside DNS queries and answers routed
through public recursive resolvers, with per-resolver capacity probing,
multi-session sizing, and a web panel for setup and management.

**Status:** Phase 2 complete. The tunnel core, the web panel
(secret path + login, setup wizard, SSH provisioning, key rotation),
and the installer are implemented and committed; the tunnel was
field-verified bidirectional between a mother server and an Iran node
(see [`docs/OPERATOR-GUIDE.md`](docs/OPERATOR-GUIDE.md)). Research
complete, core selected, plan published — see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Install

Download the installer, inspect it, then run it as a file (never
`curl | sudo bash` — artifacts are SHA-256-verified before use):

```sh
curl -fLO https://github.com/Altonomega/Nexounel/releases/download/<version>/install.sh
less install.sh
sudo bash install.sh --mother    # mother server: server + panel
sudo bash install.sh --node      # node server: node only
```

Flags include `--dry-run`, `--non-interactive`, `--uninstall`, and
`--help` (offline). The installer probes a mirror list (fastest wins,
fallback on failure), preserves configs/keys/credentials on re-run,
and writes systemd units, logrotate, and the first-run panel init.
Details: [`docs/OPERATOR-GUIDE.md`](docs/OPERATOR-GUIDE.md).

## Panel

The panel runs on the mother under one random, fixed web path plus a
username/password login (argon2id-hashed, rate-limited). It provides
status views (server health via the metrics endpoint, registry
fingerprints, redacted log tails), a setup wizard (manual DNS records
with live verification, or automatic Cloudflare record creation with
a transient-only credential — never stored), SSH provisioning of
nodes with ephemeral keypairs and verified cleanup, and per-node key
rotation. Details: [`docs/OPERATOR-GUIDE.md`](docs/OPERATOR-GUIDE.md).

**Lineage.** The tunnel core is derived from
[CottenDNS](https://github.com/WhiteDNS/CottenDNS) (itself derived from
[StormDNS](https://github.com/nullroute1970/StormDNS) and
[MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN)), under the
MIT license. See `LICENSE` for attribution. The WhiteDNS client apps are
*not* part of this project and are not reused.

Built by Mashani (Altonomega). License: MIT.
