#!/usr/bin/env bash
# Build the Nexounel release tarball + .sha256 from this repository.
#
# Run from the repository root:
#   install/package-release.sh [--version X] [--out DIR]
#
# Version precedence: --version flag, then `git describe --tags
# --always`, then a VERSION file at the repository root, then "dev".
#
# The tarball contains the three binaries (built with -trimpath and
# the link-time version), the sample configs, the systemd units, and
# the logrotate config, under one top-level directory:
#   nexounel-<version>-linux-<arch>/
# The build works offline given a Go toolchain and a populated module
# cache (GOPROXY=off). The tarball is deterministic: sorted entries,
# zero timestamps, numeric root ownership, gzip without a stored name
# or timestamp. After creation the tarball is verified by re-extracting
# it to a temporary directory, listing its contents, running each
# binary's -version flag, and checking the .sha256 sidecar.

set -euo pipefail

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: package-release.sh [--version X] [--out DIR]

  --version X   Release version stamped into the binaries and used in
                the tarball name (e.g. v3.5.0). Default: git describe
                --tags --always, then a VERSION file, then "dev".
  --out DIR     Output directory for the tarball and .sha256 file.
                Default: ./dist under the repository root.
  --help        Print this usage and exit 0.
EOF
}

VERSION_OVERRIDE=""
OUT_DIR=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version) [ "$#" -ge 2 ] || die "--version requires a value"; VERSION_OVERRIDE="$2"; shift ;;
        --version=*) VERSION_OVERRIDE="${1#--version=}" ;;
        --out) [ "$#" -ge 2 ] || die "--out requires a value"; OUT_DIR="$2"; shift ;;
        --out=*) OUT_DIR="${1#--out=}" ;;
        --help|-h) usage; exit 0 ;;
        --) shift; break ;;
        *) printf 'error: unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done
if [ "$#" -gt 0 ]; then
    printf 'error: unexpected argument: %s\n' "$1" >&2
    usage >&2
    exit 2
fi

REPO_ROOT="$(pwd)"
[ -f "$REPO_ROOT/core/go.mod" ] || die "run package-release.sh from the repository root (core/go.mod not found in $REPO_ROOT)"
[ -d "$REPO_ROOT/install/units" ] || die "install/units not found in $REPO_ROOT"
[ -f "$REPO_ROOT/install/logrotate/nexounel" ] || die "install/logrotate/nexounel not found in $REPO_ROOT"

resolve_version() {
    if [ -n "$VERSION_OVERRIDE" ]; then
        printf '%s' "$VERSION_OVERRIDE"
        return 0
    fi
    if command -v git >/dev/null 2>&1; then
        if described="$(git -C "$REPO_ROOT" describe --tags --always 2>/dev/null)" && [ -n "$described" ]; then
            printf '%s' "$described"
            return 0
        fi
    fi
    if [ -f "$REPO_ROOT/VERSION" ]; then
        if file_version="$(tr -d '[:space:]' <"$REPO_ROOT/VERSION")" && [ -n "$file_version" ]; then
            printf '%s' "$file_version"
            return 0
        fi
    fi
    printf 'dev'
}

arch_name() {
    local machine
    machine="$(uname -m)"
    case "$machine" in
        x86_64|amd64) printf 'amd64' ;;
        aarch64|arm64) printf 'arm64' ;;
        *) die "unsupported architecture: $machine (only amd64 and arm64 are supported)" ;;
    esac
}

VERSION="$(resolve_version)"
ARCH="$(arch_name)"
TARBALL_NAME="nexounel-${VERSION}-linux-${ARCH}.tar.gz"
TOP_DIR="nexounel-${VERSION}-linux-${ARCH}"

if [ -z "$OUT_DIR" ]; then
    OUT_DIR="$REPO_ROOT/dist"
fi
mkdir -p "$OUT_DIR"

command -v go >/dev/null 2>&1 || die "go toolchain not found on PATH; put the Go 1.26+ toolchain on PATH before running package-release.sh"
printf 'Using %s\n' "$(go version)"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
STAGING="$WORKDIR/$TOP_DIR"
mkdir -p "$STAGING/configs" "$STAGING/units" "$STAGING/logrotate"

LDFLAGS="-X github.com/MNSH-Nexo/Nexounel/core/internal/version.BuildVersion=${VERSION}"
export GOPROXY=off
export CGO_ENABLED=0

printf 'Building nexounel-server (%s)...\n' "$VERSION"
(cd "$REPO_ROOT/core" && go build -trimpath -ldflags "$LDFLAGS" -o "$STAGING/nexounel-server" ./cmd/nexounel-server) \
    || die "go build failed for nexounel-server"
printf 'Building nexounel-node (%s)...\n' "$VERSION"
(cd "$REPO_ROOT/core" && go build -trimpath -ldflags "$LDFLAGS" -o "$STAGING/nexounel-node" ./cmd/nexounel-node) \
    || die "go build failed for nexounel-node"
printf 'Building nexounel-panel (%s)...\n' "$VERSION"
(cd "$REPO_ROOT/core" && go build -trimpath -ldflags "$LDFLAGS" -o "$STAGING/nexounel-panel" ./cmd/nexounel-panel) \
    || die "go build failed for nexounel-panel"
chmod 755 "$STAGING/nexounel-server" "$STAGING/nexounel-node" "$STAGING/nexounel-panel"

cp -a "$REPO_ROOT/core/configs/nexounel-server.toml" "$REPO_ROOT/core/configs/nexounel-node.toml" "$REPO_ROOT/core/configs/nodes.toml.example" "$REPO_ROOT/core/configs/client_resolvers.txt" "$STAGING/configs/"
cp -a "$REPO_ROOT/install/units/nexounel.service" "$REPO_ROOT/install/units/nexounel-node.service" "$REPO_ROOT/install/units/nexounel-panel.service" "$STAGING/units/"
cp -a "$REPO_ROOT/install/logrotate/nexounel" "$STAGING/logrotate/"

TARBALL_PATH="$OUT_DIR/$TARBALL_NAME"
printf 'Creating %s ...\n' "$TARBALL_PATH"
tar --sort-name --mtime='@0' --owner=0 --group=0 --numeric-owner -cf - -C "$WORKDIR" "$TOP_DIR" | gzip -n >"$TARBALL_PATH"

(cd "$OUT_DIR" && sha256sum "$TARBALL_NAME" >"${TARBALL_NAME}.sha256")
printf 'Wrote %s\n' "$OUT_DIR/${TARBALL_NAME}.sha256"

# Verify: re-extract to a fresh directory, list contents, run each
# binary's -version flag, and check the .sha256 sidecar.
VERIFY_DIR="$(mktemp -d)"
tar -xzf "$TARBALL_PATH" -C "$VERIFY_DIR"
printf 'Tarball contents:\n'
tar -tzf "$TARBALL_PATH"
for binary in nexounel-server nexounel-node nexounel-panel; do
    "$VERIFY_DIR/$TOP_DIR/$binary" -version || die "verification failed: $binary -version did not exit 0"
done
(cd "$OUT_DIR" && sha256sum -c "${TARBALL_NAME}.sha256") || die "verification failed: sha256sum -c did not pass"
rm -rf "$VERIFY_DIR"
trap - EXIT
rm -rf "$WORKDIR"
printf 'Release tarball verified: %s\n' "$TARBALL_PATH"
