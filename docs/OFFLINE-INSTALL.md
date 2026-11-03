# Nexounel install paths: online mirror install vs offline bundle

There are two ways to install Nexounel. Both install the same
binaries, units, and sample configs, both are idempotent (re-running
upgrades the binaries and preserves configs, keys, the node registry,
and panel credentials), and neither installs OS packages or a
toolchain on the target host.

## 1. One-command mirror install (servers with network access)

The installer downloads the versioned release tarball from the
fastest mirror that serves it, verifies the SHA-256 sidecar from the
same mirror, and installs file by file. It never executes a downloaded
artifact and never pipes a download into a shell.

```sh
# Download the installer, inspect it, then run it:
curl -fLO https://github.com/MNSH-Nexo/Nexounel/releases/download/<version>/install.sh
less install.sh
sudo bash install.sh --mother    # mother server: server + panel
sudo bash install.sh --node      # node server: node only
```

Options: `--release <version>` (required for the download path),
`--mirror <url>` (repeatable, prepended to the mirror list),
`NEXOUNEL_MIRRORS` (comma-separated, replaces the default list),
`--non-interactive`, `--dry-run` (prints every action, works offline),
`--uninstall`. Full reference: `install/README.md` and
`install.sh --help`.

## 2. Offline bundle (servers without reliable network or mirrors)

When the target server cannot reach GitHub or any mirror — broken
package sources, filtered egress, or an air-gapped host — download
ONE bundle once, by any means (even on another machine), copy it to
the server, and install with zero network access and zero external
downloads.

The bundle is built from the repository with:

```sh
install/package-offline-bundle.sh [--version X] [--out DIR]
```

It produces `nexounel-<version>-offline.tar.gz` plus a `.sha256`
sidecar, containing: `install.sh`, the three binaries for **both**
`linux/amd64` and `linux/arm64` (static, `CGO_ENABLED=0`), a
`SHA256SUMS` file covering every binary, the systemd units, the
logrotate config, and the sample configs.

Install on the target host:

```sh
tar -xzf nexounel-<version>-offline.tar.gz
cd nexounel-<version>-offline

# Mother (server + panel):
sudo ./install.sh --mother --tarball ../nexounel-<version>-offline.tar.gz

# Node, no prompts:
sudo ./install.sh --node --tarball ../nexounel-<version>-offline.tar.gz --non-interactive
```

Keep the `.tar.gz` and its `.sha256` sidecar next to the extracted
directory: the installer verifies the whole bundle against the
sidecar automatically (or pass `--sha256 <hash>` explicitly), then
verifies the selected binaries against the bundle's `SHA256SUMS`.
The host architecture is detected automatically; a bundle without
binaries for the host architecture fails loudly instead of
installing the wrong binaries. No `curl` is required and no network
call of any kind is made on this path.

Uninstall from the extracted bundle directory (no tarball needed):

```sh
sudo ./install.sh --uninstall
```

## Which path to use

| Situation | Path |
| --- | --- |
| Server reaches GitHub or a mirror | Mirror install (simpler, smaller download) |
| Broken mirrors / filtered egress / air-gapped | Offline bundle (one download, zero network at install) |
| Building from source is required | `--build-from-source` (opt-in, downloads and hash-verifies a Go toolchain and the source tarball; see `install/README.md`) |

## Notes shared by both paths

- Bind a specific IP in `nexounel-server.toml` (`UDP_HOST`), not
  `0.0.0.0`: systemd-resolved owns loopback stubs on :53.
- Firewall rules are NOT applied by the installer. The mother needs
  inbound UDP/TCP 53; nodes need nothing inbound.
- `--destdir ROOT` prefixes every path and disables all systemctl
  calls (testing only).
