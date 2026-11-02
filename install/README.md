# Nexounel installer

One flat command, NexoShield-style. Installs the server (mother), the
node, and the panel from a versioned release tarball. Idempotent and
resumable: re-running upgrades binaries and preserves existing
configs, keys, the node registry, and panel credentials.

## Install

```sh
# Mother (server + panel), interactive first-run panel init:
./install/install.sh --mother --release v3.5.0

# Node, no prompts (panel init is a mother-only step):
./install/install.sh --node --release v3.5.0 --non-interactive

# Both, from a local tarball (hash required):
./install/install.sh --mother --node \
  --tarball /tmp/nexounel-v3.5.0-linux-amd64.tar.gz --sha256 <hash> \
  --non-interactive

# Preview only; prints every action, changes nothing, works offline:
./install/install.sh --dry-run --mother
```

Run as root for a real install. `--help` works fully offline.

The installer downloads the release tarball plus its `.sha256` sidecar
from the same mirror, verifies the hash before extraction, extracts to
a staging directory, and installs file by file. It never executes a
downloaded artifact and never pipes a download into a shell.

### Mirrors

Every download is probed across the mirror list with a short HEAD
request; the fastest mirror returning HTTP 200 serves the artifact,
and any download failure falls through to the next mirror. Configure
the list with repeatable `--mirror URL` flags (prepended, first wins)
or the `NEXOUNEL_MIRRORS` environment variable (comma-separated,
replaces the defaults). Custom mirrors must serve the GitHub releases
path layout (`.../MNSH-Nexo/Nexounel/releases/download/<version>/<artifact>`).
See the comment block at the top of `install.sh` for the format; add
Iranian mirrors there by prepending their URLs, do not edit the
defaults in place without verifying the host serves the artifacts.

### Source-build fallback

`--build-from-source` builds the three binaries from the tagged source
tarball instead of using a release tarball. It requires `--release`,
`--go-sha256`, and `--source-sha256` and fails closed when any hash is
absent. A usable Go 1.26+ toolchain on `PATH` is reused; otherwise the
toolchain tarball is downloaded, hash-verified, and cached under
`/opt/nexounel/.build` (root) or `~/.cache/nexounel`.

### First-run panel init

With `--mother` and an interactive terminal, the installer prompts for
an admin password (twice, minimum 12 characters) and runs
`nexounel-panel -init`, which writes `nexounel-panel.toml` (0600) with
the webpath token, session key, and hashed password. With
`--non-interactive` no credentials are written and the panel service
is left disabled; initialize it manually:

```sh
nexounel-panel -init
nexounel-panel -check-config
systemctl enable --now nexounel-panel.service
```

### Port 53

Bind a specific IP in `nexounel-server.toml` (`UDP_HOST`), not
`0.0.0.0`: systemd-resolved owns loopback stubs on :53 and a wildcard
bind conflicts with them. The sample config ships a wildcard default;
change it before production use. The installer prints firewall notes
only and applies no firewall rules: the mother needs inbound UDP/TCP
53, nodes need nothing inbound.

## Uninstall

```sh
./install/install.sh --uninstall
```

Stops and disables the units, removes binaries, units, and the
logrotate file, and asks (default NO) before deleting configs that
hold keys. `--non-interactive` always preserves configs. Nothing
outside `/opt/nexounel`, its units, and the logrotate file is touched;
logs in `/var/log/nexounel` are left in place.

## Release packaging

```sh
install/package-release.sh [--version X] [--out DIR]
```

Builds the three binaries with `-trimpath` and the link-time version
(version precedence: `--version`, `git describe --tags --always`, a
`VERSION` file, then `dev`), assembles the staging tree, and writes a
deterministic `nexounel-<version>-linux-<arch>.tar.gz` plus a
`.sha256` sidecar. The script re-extracts the tarball, lists its
contents, runs each binary's `-version` flag, and checks the sidecar.
It works offline given a Go toolchain and a populated module cache.

## Layout

| Path | Contents |
| --- | --- |
| `install/install.sh` | The installer |
| `install/package-release.sh` | Release tarball builder |
| `install/units/` | `nexounel.service`, `nexounel-node.service`, `nexounel-panel.service` |
| `install/logrotate/nexounel` | Logrotate config (daily, 7 days) |

Installed system layout: binaries and configs in `/opt/nexounel`,
units in `/etc/systemd/system`, logrotate in `/etc/logrotate.d`,
logs in `/var/log/nexounel`. `--destdir ROOT` prefixes every path
and disables all systemctl calls (testing only).
