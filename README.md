# Nexounel

A DNS-based tunnel between two servers (one inside Iran, one outside),
built for emergency-grade stability when ordinary paths are blocked or
degraded. It carries TCP streams inside DNS queries and answers routed
through public recursive resolvers, with per-resolver capacity probing,
multi-session sizing, and a web panel for setup and management.

**Status:** architecture phase. Research complete, core selected,
initial plan published. No tunnel code yet — see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

**Lineage.** The tunnel core is derived from
[CottenDNS](https://github.com/WhiteDNS/CottenDNS) (itself derived from
[StormDNS](https://github.com/nullroute1970/StormDNS) and
[MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN)), under the
MIT license. See `LICENSE` for attribution. The WhiteDNS client apps are
*not* part of this project and are not reused.

Built by Mashani (MNSH-Nexo). License: MIT.
