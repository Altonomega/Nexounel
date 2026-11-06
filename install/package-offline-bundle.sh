#!/usr/bin/env bash
# Build the Nexounel OFFLINE bundle + .sha256 from this repository.
#
# Run from the repository root:
#   install/package-offline-bundle.sh [--version X] [--out DIR]
#
# Version precedence: --version flag, then `git describe --tags
# --always`, then a VERSION file at the repository root, then "dev".
#
# The bundle is ONE self-contained tarball for servers without
# reliable network access or working mirrors/package sources:
#   nexounel-<version>-offline/
#     install.sh            the installer (copied from install/)
#     README.md             quick-start (English + Persian)
#     SHA256SUMS            SHA-256 of every binary in the bundle
#     linux-amd64/          the three binaries for amd64
#     linux-arm64/          the three binaries for arm64
#     configs/              sample configs + default resolver list
#     units/                systemd units
#     logrotate/            logrotate config
# Installing from the bundle with `install.sh --tarball` is fully
# offline: no download, no curl, and the binaries for the host
# architecture are verified against SHA256SUMS before installation.
#
# The build works offline given a Go toolchain and a populated module
# cache (GOPROXY=off). Binaries are static (CGO_ENABLED=0). The
# tarball is deterministic: sorted entries, zero timestamps, numeric
# root ownership, gzip without a stored name or timestamp. After
# creation the bundle is verified by re-extracting it, listing its
# contents, running each amd64 binary's -version flag, checking the
# arm64 binaries' build settings with `go version -m` and their
# embedded version stamp (they cannot execute on an amd64 build
# host), verifying SHA256SUMS, and checking the .sha256 sidecar.

set -euo pipefail

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: package-offline-bundle.sh [--version X] [--out DIR]

  --version X   Release version stamped into the binaries and used in
                the bundle name (e.g. v3.5.0). Default: git describe
                --tags --always, then a VERSION file, then "dev".
  --out DIR     Output directory for the bundle tarball and .sha256
                file. Default: ./dist under the repository root.
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
[ -f "$REPO_ROOT/core/go.mod" ] || die "run package-offline-bundle.sh from the repository root (core/go.mod not found in $REPO_ROOT)"
[ -d "$REPO_ROOT/install/units" ] || die "install/units not found in $REPO_ROOT"
[ -f "$REPO_ROOT/install/logrotate/nexounel" ] || die "install/logrotate/nexounel not found in $REPO_ROOT"
[ -f "$REPO_ROOT/install/install.sh" ] || die "install/install.sh not found in $REPO_ROOT"
[ -f "$REPO_ROOT/install/README-offline-bundle.md" ] || die "install/README-offline-bundle.md not found in $REPO_ROOT"

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

VERSION="$(resolve_version)"
BUNDLE_NAME="nexounel-${VERSION}-offline.tar.gz"
TOP_DIR="nexounel-${VERSION}-offline"

if [ -z "$OUT_DIR" ]; then
    OUT_DIR="$REPO_ROOT/dist"
fi
mkdir -p "$OUT_DIR"

command -v go >/dev/null 2>&1 || die "go toolchain not found on PATH; put the Go 1.26+ toolchain on PATH before running package-offline-bundle.sh"
printf 'Using %s\n' "$(go version)"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
STAGING="$WORKDIR/$TOP_DIR"
mkdir -p "$STAGING/linux-amd64" "$STAGING/linux-arm64" "$STAGING/configs" "$STAGING/units" "$STAGING/logrotate"

LDFLAGS="-X github.com/Altonomega/Nexounel/core/internal/version.BuildVersion=${VERSION}"
export GOPROXY=off
export CGO_ENABLED=0

for arch in amd64 arm64; do
    for binary in nexounel-server nexounel-node nexounel-panel; do
        printf 'Building %s (%s, %s)...\n' "$binary" "$VERSION" "$arch"
        (cd "$REPO_ROOT/core" && GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "$LDFLAGS" -o "$STAGING/linux-$arch/$binary" "./cmd/$binary") \
            || die "go build failed for $binary ($arch)"
    done
    chmod 755 "$STAGING/linux-$arch"/nexounel-*
done

cp -a "$REPO_ROOT/install/install.sh" "$STAGING/install.sh"
cp -a "$REPO_ROOT/install/README-offline-bundle.md" "$STAGING/README.md"
cp -a "$REPO_ROOT/core/configs/nexounel-server.toml" "$REPO_ROOT/core/configs/nexounel-node.toml" "$REPO_ROOT/core/configs/nodes.toml.example" "$REPO_ROOT/core/configs/client_resolvers.txt" "$STAGING/configs/"
cp -a "$REPO_ROOT/install/units/nexounel.service" "$REPO_ROOT/install/units/nexounel-node.service" "$REPO_ROOT/install/units/nexounel-panel.service" "$STAGING/units/"
cp -a "$REPO_ROOT/install/logrotate/nexounel" "$STAGING/logrotate/"

# SHA256SUMS covers every binary in the bundle, with paths relative
# to the bundle root, so the installer can verify the selected
# architecture's binaries with `sha256sum -c SHA256SUMS` after
# extraction. Sorted for determinism.
(cd "$STAGING" && sha256sum linux-amd64/nexounel-* linux-arm64/nexounel-* | LC_ALL=C sort >SHA256SUMS)

# Normalize modes so the bundle is reproducible regardless of the
# checkout's umask or the staging parent's setgid bit (directory
# modes otherwise leak into the tar headers): directories 0755,
# regular files 0644, binaries and the installer 0755. The installer
# applies its own modes at install time, so this only affects the
# tarball itself. SHA256SUMS covers file contents only and is
# unaffected by modes.
find "$STAGING" -type d -exec chmod 755 {} +
find "$STAGING" -type f -exec chmod 644 {} +
chmod 755 "$STAGING"/linux-*/nexounel-* "$STAGING/install.sh"

BUNDLE_PATH="$OUT_DIR/$BUNDLE_NAME"
printf 'Creating %s ...\n' "$BUNDLE_PATH"
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -cf - -C "$WORKDIR" "$TOP_DIR" | gzip -n >"$BUNDLE_PATH"

(cd "$OUT_DIR" && sha256sum "$BUNDLE_NAME" >"${BUNDLE_NAME}.sha256")
printf 'Wrote %s\n' "$OUT_DIR/${BUNDLE_NAME}.sha256"

# Verify: re-extract to a fresh directory, list contents, run each
# amd64 binary's -version flag, check the arm64 binaries' build
# settings with `go version -m`, verify SHA256SUMS, and check the
# .sha256 sidecar.
VERIFY_DIR="$(mktemp -d)"
tar -xzf "$BUNDLE_PATH" -C "$VERIFY_DIR"
printf 'Bundle contents:\n'
tar -tzf "$BUNDLE_PATH"
for binary in nexounel-server nexounel-node nexounel-panel; do
    "$VERIFY_DIR/$TOP_DIR/linux-amd64/$binary" -version || die "verification failed: linux-amd64/$binary -version did not exit 0"
    go version -m "$VERIFY_DIR/$TOP_DIR/linux-arm64/$binary" | grep -q "GOARCH=arm64" || die "verification failed: linux-arm64/$binary is not an arm64 binary"
    # The arm64 binary cannot execute on an amd64 build host; the
    # -X version stamp is checked as an embedded string instead.
    grep -a -q -F "$VERSION" "$VERIFY_DIR/$TOP_DIR/linux-arm64/$binary" || die "verification failed: linux-arm64/$binary does not carry version ${VERSION}"
done
(cd "$VERIFY_DIR/$TOP_DIR" && sha256sum -c SHA256SUMS) || die "verification failed: SHA256SUMS did not pass"
(cd "$OUT_DIR" && sha256sum -c "${BUNDLE_NAME}.sha256") || die "verification failed: sha256sum -c did not pass"
rm -rf "$VERIFY_DIR"
trap - EXIT
rm -rf "$WORKDIR"
printf 'Offline bundle verified: %s\n' "$BUNDLE_PATH"
