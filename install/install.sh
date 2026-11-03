#!/usr/bin/env bash
# Nexounel installer: installs the server (mother), the node, and the
# panel from a versioned release tarball. Idempotent and resumable:
# re-running upgrades binaries and preserves existing configs, keys,
# the node registry, and panel credentials.
#
# The installer is downloaded, inspected, and run as a file. It never
# pipes a download into a shell, never executes a downloaded artifact,
# and verifies every downloaded tarball with SHA-256 before extraction.
#
# Mirror configuration: every download is probed across the mirror
# list and fetched from the fastest mirror that serves the artifact
# (HTTP 200 on HEAD), falling through to the next mirror on failure.
# The default list is operator-configurable:
#   * NEXOUNEL_MIRRORS environment variable, comma-separated, replaces
#     the default list entirely.
#   * --mirror URL flags prepend to the list (first --mirror wins).
# Custom mirrors must serve the GitHub releases path layout, e.g.:
#   # https://your-mirror.example.invalid/MNSH-Nexo/Nexounel/releases/download/<version>/<artifact>
# To add an Iranian mirror, point it at a host that mirrors
# github.com releases under that path layout and prepend it with
# --mirror or NEXOUNEL_MIRRORS. No mirror hostname is hardcoded here
# beyond the three well-known defaults below, and no unverified
# mirror hostname is invented by this script.
#
# Offline bundle: a self-contained tarball
# (nexounel-<version>-offline.tar.gz) built by
# install/package-offline-bundle.sh contains install.sh, the binaries
# for amd64 and arm64, units, logrotate config, sample configs, and a
# SHA256SUMS file. Installing from a bundle with --tarball is fully
# offline: no download, no curl, and the selected binaries are
# verified against the bundle's SHA256SUMS before installation.
#
# Layout (overridable ONLY via --destdir for testing; --destdir ROOT
# prefixes every path, including systemd units, and disables all
# systemctl/service actions):
#   binaries:  /opt/nexounel/nexounel-{server,node,panel}  (0755)
#   configs:   /opt/nexounel/*.toml, nodes.toml            (0600)
#   units:     /etc/systemd/system/nexounel*.service       (0644)
#   logrotate: /etc/logrotate.d/nexounel
#   logs dir:  /var/log/nexounel                           (0755)

set -euo pipefail

INSTALLER_VERSION="1.0.0"
REPO_OWNER="MNSH-Nexo"
REPO_NAME="Nexounel"

# Defaults. The server bind address is a CONFIG value, not an
# installer flag: edit UDP_HOST in nexounel-server.toml after install.
# Bind a specific IP on port 53, not 0.0.0.0: systemd-resolved owns
# loopback stubs on :53 and a wildcard bind conflicts with it.
# See the post-install note printed by this script.
DEFAULT_MIRRORS=(
    "https://github.com"
    "https://objects.githubusercontent.com"
    "https://mirror.ghproxy.com"
)

MODE_MOTHER=0
MODE_NODE=0
DRY_RUN=0
DO_UNINSTALL=0
NON_INTERACTIVE=0
BUILD_FROM_SOURCE=0
DESTDIR=""
TARBALL=""
SHA256_OVERRIDE=""
GO_SHA256=""
SOURCE_SHA256=""
RELEASE_VERSION=""
GO_VERSION="1.26.10"
MIRROR_EXTRA=()

# Set during acquisition: BINARY_ROOT is where the installable binaries
# live inside the staging tree (the staging root for flat release
# tarballs and source builds, or the per-architecture subdirectory
# for offline bundles).
BINARY_ROOT=""

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

note() {
    printf '%s\n' "$*"
}

warn() {
    printf 'warning: %s\n' "$*" >&2
}

usage() {
    cat <<'EOF'
Usage: install.sh --mother|--node [options]

Modes (at least one is required; both together installs everything):
  --mother            Install the server (mother) + panel binaries, the
                      server sample config, and the panel unit.
  --node              Install the node binary, the node sample config,
                      and the node unit.
  Both modes install the shared bits: directories, logrotate config,
  and the resolver list (only when absent).

Options:
  --dry-run           Print every action without doing anything. Works
                      offline; performs no downloads and no prompts.
  --uninstall         Remove units, binaries, and the logrotate file.
                      Asks before deleting configs that hold keys;
                      with --non-interactive, configs are preserved.
  --help              Print this usage and exit 0.
  --version           Print the installer version and exit 0.
  --non-interactive   Never prompt. The panel is left uninitialized:
                      no credentials are written; run
                      `nexounel-panel -init` manually afterwards.
  --destdir ROOT      Prefix every install path with ROOT (testing
                      only). Disables all systemctl calls, service
                      starts, and the interactive password prompt.
  --tarball PATH      Install from a local release tarball instead of
                      downloading one. Requires --sha256, or a sibling
                      <tarball>.sha256 file next to the tarball.
                      An offline bundle (nexounel-<version>-offline.tar.gz)
                      works here too and installs fully offline: no
                      download and no curl; binaries for this host's
                      architecture are picked from the bundle and
                      verified against its SHA256SUMS.
  --sha256 HASH       Expected SHA-256 of the release tarball. Verifies
                      a local --tarball, and additionally pins a
                      downloaded tarball.
  --release VERSION   Release version to download (e.g. v3.5.0).
                      Required for the download path.
  --mirror URL        Prepend URL to the mirror list. Repeatable.
                      NEXOUNEL_MIRRORS (comma-separated) replaces the
                      default mirror list.
  --build-from-source Build the binaries from the tagged source
                      tarball instead of using a release tarball.
                      Requires --release, --go-sha256, and
                      --source-sha256.
  --go-sha256 HASH    Expected SHA-256 of the Go toolchain tarball.
                      Required when the toolchain must be downloaded
                      for a source build; the script fails closed
                      without it.
  --source-sha256 HASH
                      Expected SHA-256 of the source tarball. Required
                      for --build-from-source.
  --go-version X      Go toolchain version for a source build
                      (default: 1.26.10).

Examples:
  install.sh --mother --release v3.5.0
  install.sh --node --release v3.5.0 --non-interactive
  install.sh --mother --node --tarball /tmp/nexounel-v3.5.0-linux-amd64.tar.gz --sha256 <hash> --non-interactive
  install.sh --mother --node --tarball /tmp/nexounel-v3.5.0-offline.tar.gz --sha256 <hash> --non-interactive
  install.sh --dry-run --mother
  install.sh --uninstall --non-interactive
EOF
}

# --- argument parsing -------------------------------------------------------

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --mother) MODE_MOTHER=1 ;;
            --node) MODE_NODE=1 ;;
            --dry-run) DRY_RUN=1 ;;
            --uninstall) DO_UNINSTALL=1 ;;
            --help|-h) usage; exit 0 ;;
            --version) printf 'nexounel-installer %s\n' "$INSTALLER_VERSION"; exit 0 ;;
            --non-interactive) NON_INTERACTIVE=1 ;;
            --build-from-source) BUILD_FROM_SOURCE=1 ;;
            --destdir) [ "$#" -ge 2 ] || die "--destdir requires a value"; DESTDIR="$2"; shift ;;
            --destdir=*) DESTDIR="${1#--destdir=}" ;;
            --tarball) [ "$#" -ge 2 ] || die "--tarball requires a value"; TARBALL="$2"; shift ;;
            --tarball=*) TARBALL="${1#--tarball=}" ;;
            --sha256) [ "$#" -ge 2 ] || die "--sha256 requires a value"; SHA256_OVERRIDE="$2"; shift ;;
            --sha256=*) SHA256_OVERRIDE="${1#--sha256=}" ;;
            --release) [ "$#" -ge 2 ] || die "--release requires a value"; RELEASE_VERSION="$2"; shift ;;
            --release=*) RELEASE_VERSION="${1#--release=}" ;;
            --mirror) [ "$#" -ge 2 ] || die "--mirror requires a value"; MIRROR_EXTRA+=("$2"); shift ;;
            --mirror=*) MIRROR_EXTRA+=("${1#--mirror=}") ;;
            --go-sha256) [ "$#" -ge 2 ] || die "--go-sha256 requires a value"; GO_SHA256="$2"; shift ;;
            --go-sha256=*) GO_SHA256="${1#--go-sha256=}" ;;
            --source-sha256) [ "$#" -ge 2 ] || die "--source-sha256 requires a value"; SOURCE_SHA256="$2"; shift ;;
            --source-sha256=*) SOURCE_SHA256="${1#--source-sha256=}" ;;
            --go-version) [ "$#" -ge 2 ] || die "--go-version requires a value"; GO_VERSION="$2"; shift ;;
            --go-version=*) GO_VERSION="${1#--go-version=}" ;;
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
}

# --- path helpers -----------------------------------------------------------
# DESTDIR prefixes every path. With no --destdir the paths are absolute
# system paths. Trailing slashes on DESTDIR are stripped.

strip_trailing_slash() {
    local path="$1"
    while [ "$path" != "/" ] && [ "${path%/}" != "$path" ]; do
        path="${path%/}"
    done
    printf '%s' "$path"
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

# --- mirrors and downloads --------------------------------------------------
# Every download resolves through the mirror list: each mirror base is
# probed with a short HEAD request and the fastest mirror returning
# HTTP 200 for the artifact is tried first; any download failure falls
# through to the next mirror. A SHA-256 mismatch aborts immediately:
# a corrupt artifact is not retried from another mirror.

build_mirror_list() {
    MIRRORS=()
    if [ -n "${NEXOUNEL_MIRRORS:-}" ]; then
        local entry rest
        rest="${NEXOUNEL_MIRRORS}"
        while [ -n "$rest" ]; do
            case "$rest" in
                *,*) entry="${rest%%,*}"; rest="${rest#*,}" ;;
                *) entry="$rest"; rest="" ;;
            esac
            entry="$(printf '%s' "$entry" | tr -d '[:space:]')"
            if [ -n "$entry" ]; then
                MIRRORS+=("$entry")
            fi
        done
    else
        MIRRORS=("${DEFAULT_MIRRORS[@]}")
    fi
    if [ "${#MIRROR_EXTRA[@]}" -gt 0 ]; then
        MIRRORS=("${MIRROR_EXTRA[@]}" "${MIRRORS[@]}")
    fi
    [ "${#MIRRORS[@]}" -gt 0 ] || die "mirror list is empty"
}

# Map a mirror base + a github.com-style path to a fetchable URL.
# ghproxy mirrors expect the full upstream URL appended to the base;
# every other base serves the releases path layout directly.
mirror_url() {
    local base="$1" path="$2"
    case "$base" in
        *mirror.ghproxy.com*) printf '%s%s%s' "$base" "/https://github.com" "$path" ;;
        *) printf '%s%s' "$base" "$path" ;;
    esac
}

# Probe every mirror with HEAD and print, fastest first, the bases
# that returned HTTP 200 for the artifact. Prints nothing when none
# did. Never fails the script: callers fall back to listed order.
probe_mirrors() {
    local path="$1" base url probe_file probe_code probe_time probe_out
    probe_file="$(mktemp)"
    for base in "${MIRRORS[@]}"; do
        url="$(mirror_url "$base" "$path")"
        probe_code=""
        probe_time=""
        if probe_out="$(curl -fsSI --max-time 10 -o /dev/null -w '%{http_code} %{time_total}' "$url" 2>/dev/null)"; then
            probe_code="${probe_out%% *}"
            probe_time="${probe_out##* }"
        fi
        if [ "$probe_code" = "200" ]; then
            printf '%s %s\n' "$probe_time" "$base" >>"$probe_file"
        fi
    done
    if [ -s "$probe_file" ]; then
        sort -n "$probe_file" | while IFS=' ' read -r _time base; do
            printf '%s\n' "$base"
        done
    fi
    rm -f "$probe_file"
}

# Download one artifact path to a destination file, trying mirrors in
# probed (fastest-first) order, falling back to listed order when no
# probe succeeded. Sets CHOSEN_MIRROR to the base that served it.
CHOSEN_MIRROR=""
download_artifact() {
    local path="$1" dest="$2" ordered base url
    ordered="$(probe_mirrors "$path")"
    if [ -z "$ordered" ]; then
        warn "no mirror returned HTTP 200 for $path on HEAD probe; trying mirrors in listed order"
        ordered="$(printf '%s\n' "${MIRRORS[@]}")"
    fi
    while IFS= read -r base; do
        [ -n "$base" ] || continue
        url="$(mirror_url "$base" "$path")"
        note "Downloading $url"
        if curl -fSL --show-error --max-time 120 -o "$dest" "$url"; then
            CHOSEN_MIRROR="$base"
            return 0
        fi
        warn "download failed from $base; trying the next mirror"
    done <<<"$ordered"
    return 1
}

# Download the same artifact path from one specific mirror base.
# Used for the .sha256 sidecar, which must come from the SAME mirror
# that served the tarball.
download_from_mirror() {
    local base="$1" path="$2" dest="$3" url
    url="$(mirror_url "$base" "$path")"
    note "Downloading $url"
    curl -fSL --show-error --max-time 60 -o "$dest" "$url"
}

# --- SHA-256 verification ---------------------------------------------------

sha256_of_file() {
    sha256sum "$1" | awk '{print $1}'
}

verify_sha256_value() {
    local file="$1" expected="$2" actual
    expected="$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')"
    actual="$(sha256_of_file "$file")"
    if [ "$actual" != "$expected" ]; then
        die "SHA-256 mismatch for $file: expected $expected, got $actual; aborting"
    fi
    note "SHA-256 verified for $file"
}

# Verify a downloaded file against a sha256sum-format sidecar file
# (the "<hash>  <filename>" format package-release.sh writes).
verify_sha256_sidecar() {
    local dir="$1" sidecar="$2"
    (cd "$dir" && sha256sum -c "$sidecar") || die "SHA-256 verification failed for the downloaded tarball; aborting"
}

# --- filesystem helpers -----------------------------------------------------
# Every mutating helper honors --dry-run: it prints the action and
# changes nothing. --destdir only changes the paths; the helpers are
# the same.

ensure_dir() {
    local dir="$1" mode="$2"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] mkdir -p %s (mode %s)\n' "$dir" "$mode"
        return 0
    fi
    mkdir -p "$dir"
    chmod "$mode" "$dir"
}

backup_file() {
    local file="$1" stamp backup
    [ -e "$file" ] || return 0
    stamp="$(date +%Y%m%d-%H%M%S)"
    backup="${file}.bak-${stamp}"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] back up %s to %s\n' "$file" "$backup"
        return 0
    fi
    cp -a "$file" "$backup"
    note "Backed up $file to $backup (backups are never deleted automatically)"
}

install_file() {
    local src="$1" dest="$2" mode="$3"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] install -m %s %s -> %s\n' "$mode" "$src" "$dest"
        return 0
    fi
    [ -e "$src" ] || die "staging file missing, cannot install: $src"
    if [ -e "$dest" ]; then
        backup_file "$dest"
    fi
    install -m "$mode" "$src" "$dest"
}

# Install a config file ONLY when absent. Existing configs, keys, and
# the registry are never overwritten.
install_config_if_absent() {
    local src="$1" dest="$2" mode="$3"
    if [ -e "$dest" ]; then
        note "Preserving existing config: $dest"
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] install -m %s %s -> %s (only if absent)\n' "$mode" "$src" "$dest"
        return 0
    fi
    [ -e "$src" ] || die "staging config missing, cannot install: $src"
    install -m "$mode" "$src" "$dest"
    note "Installed sample config: $dest (edit it before relying on it)"
}

# systemctl is never invoked in --destdir mode and never in --dry-run
# mode: the wrapper prints what would happen instead. All systemctl
# calls in this script go through this wrapper so a DESTDIR install
# is provably system-touch-free.
run_systemctl() {
    if [ -n "$DESTDIR" ]; then
        printf 'DESTDIR mode: systemctl skipped: systemctl %s\n' "$*"
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] systemctl %s\n' "$*"
        return 0
    fi
    command systemctl "$@"
}

# --- tarball handling -------------------------------------------------------
# A tarball is never executed. It is extracted to a staging directory,
# its contents are validated, and files are then installed one by one
# with install(1). Tar entries with absolute paths or ".." components
# are rejected before extraction.

validate_tarball_entries() {
    local tarball="$1" entry
    while IFS= read -r entry; do
        case "$entry" in
            /*|..|../*|*/../*) die "unsafe entry in tarball, refusing to extract: $entry" ;;
        esac
    done < <(tar -tzf "$tarball")
}

extract_tarball() {
    local tarball="$1" staging="$2"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] verify SHA-256, then extract %s to a staging directory\n' "$tarball"
        return 0
    fi
    validate_tarball_entries "$tarball"
    mkdir -p "$staging"
    tar -xzf "$tarball" -C "$staging"
}

# The release tarball has one top-level directory. Print its path.
staging_root() {
    local staging="$1" entry
    entry="$(tar -tzf "$2" | head -n 1)"
    entry="${entry%%/*}"
    [ -n "$entry" ] || die "empty release tarball"
    printf '%s/%s' "$staging" "$entry"
}

# Validate the staging contents required by the selected modes before
# anything is installed. Missing files fail closed with the full list.
# Binaries are checked under BINARY_ROOT (set by the acquisition step:
# the staging root, or the per-arch subdirectory of an offline bundle);
# configs, units, and logrotate are checked under the staging root.
validate_staging() {
    local root="$1" missing=""
    if [ "$MODE_MOTHER" -eq 1 ]; then
        [ -x "$BINARY_ROOT/nexounel-server" ] || missing="$missing nexounel-server"
        [ -x "$BINARY_ROOT/nexounel-panel" ] || missing="$missing nexounel-panel"
    fi
    if [ "$MODE_NODE" -eq 1 ]; then
        [ -x "$BINARY_ROOT/nexounel-node" ] || missing="$missing nexounel-node"
    fi
    if [ "$MODE_MOTHER" -eq 1 ]; then
        [ -f "$root/configs/nexounel-server.toml" ] || missing="$missing configs/nexounel-server.toml"
        [ -f "$root/units/nexounel.service" ] || missing="$missing units/nexounel.service"
        [ -f "$root/units/nexounel-panel.service" ] || missing="$missing units/nexounel-panel.service"
    fi
    if [ "$MODE_NODE" -eq 1 ]; then
        [ -f "$root/configs/nexounel-node.toml" ] || missing="$missing configs/nexounel-node.toml"
        [ -f "$root/units/nexounel-node.service" ] || missing="$missing units/nexounel-node.service"
    fi
    [ -f "$root/configs/nodes.toml.example" ] || missing="$missing configs/nodes.toml.example"
    [ -f "$root/configs/client_resolvers.txt" ] || missing="$missing configs/client_resolvers.txt"
    [ -f "$root/logrotate/nexounel" ] || missing="$missing logrotate/nexounel"
    if [ -n "$missing" ]; then
        die "release tarball is missing required files:$missing"
    fi
}

# Decide where the installable binaries live inside an extracted
# tarball, and set BINARY_ROOT. Offline bundles carry
# per-architecture subdirectories (linux-amd64/, linux-arm64/) plus a
# SHA256SUMS file; plain release tarballs carry flat binaries at the
# staging root. Bundle binaries are verified against SHA256SUMS before
# anything is installed, and a bundle without binaries for this
# architecture fails loudly instead of installing another
# architecture's binaries.
setup_binary_root() {
    local root="$1" arch="$2" arch_dir provided entry
    if [ -d "$root/linux-amd64" ] || [ -d "$root/linux-arm64" ]; then
        arch_dir="$root/linux-$arch"
        if [ ! -d "$arch_dir" ]; then
            provided=""
            for entry in "$root"/linux-*/; do
                [ -d "$entry" ] || continue
                provided="$provided $(basename "$entry")"
            done
            die "offline bundle has no binaries for this architecture ($arch); bundle provides:${provided:- none}"
        fi
        [ -f "$root/SHA256SUMS" ] || die "offline bundle is missing SHA256SUMS; refusing to install unverified binaries"
        (cd "$root" && sha256sum -c SHA256SUMS) || die "SHA256SUMS verification failed for the offline bundle; aborting"
        note "Offline bundle: SHA256SUMS verified, using binaries for $arch"
        BINARY_ROOT="$arch_dir"
    else
        BINARY_ROOT="$root"
    fi
}

# --- local tarball acquisition ----------------------------------------------

acquire_from_local_tarball() {
    local arch="$1" tarball="$2" staging="$3" sidecar expected
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] verify %s against its SHA-256, then extract it to a staging directory\n' "$tarball"
        STAGING_ROOT="<staging>"
        # A bundle listing is readable offline; reflect the per-arch
        # binary path in dry-run output when the tarball is a bundle.
        if tar -tzf "$tarball" 2>/dev/null | grep -q "linux-${arch}/nexounel-server"; then
            BINARY_ROOT="<staging>/linux-$arch"
        else
            BINARY_ROOT="<staging>"
        fi
        return 0
    fi
    [ -f "$tarball" ] || die "tarball not found: $tarball"
    if [ -n "$SHA256_OVERRIDE" ]; then
        verify_sha256_value "$tarball" "$SHA256_OVERRIDE"
    elif [ -f "${tarball}.sha256" ]; then
        sidecar="${tarball}.sha256"
        expected="$(awk '{print $1}' "$sidecar")"
        verify_sha256_value "$tarball" "$expected"
    else
        die "--tarball requires --sha256 HASH or a sibling ${tarball}.sha256 file; refusing to install an unverified tarball"
    fi
    extract_tarball "$tarball" "$staging"
    STAGING_ROOT="$(staging_root "$staging" "$tarball")"
    setup_binary_root "$STAGING_ROOT" "$arch"
    validate_staging "$STAGING_ROOT"
}

# --- download acquisition ---------------------------------------------------

acquire_from_download() {
    local arch="$1" staging="$2" workdir="$3"
    local artifact sha_artifact path sha_path tarball_file
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] probe mirrors %s\n' "$(printf '%s,' "${MIRRORS[@]}" | sed 's/,$//')"
        printf '[dry-run] download nexounel-%s-linux-%s.tar.gz and its .sha256 from the fastest mirror, verify SHA-256, then extract to a staging directory\n' "${RELEASE_VERSION:-<release>}" "$arch"
        STAGING_ROOT="<staging>"
        return 0
    fi
    [ -n "$RELEASE_VERSION" ] || die "no release version given: pass --release <version> (e.g. v3.5.0), or use --tarball PATH"
    artifact="nexounel-${RELEASE_VERSION}-linux-${arch}.tar.gz"
    sha_artifact="${artifact}.sha256"
    path="/${REPO_OWNER}/${REPO_NAME}/releases/download/${RELEASE_VERSION}/${artifact}"
    sha_path="${path}.sha256"
    tarball_file="${workdir}/${artifact}"
    if ! download_artifact "$path" "$tarball_file"; then
        die "could not download $artifact from any mirror"
    fi
    if ! download_from_mirror "$CHOSEN_MIRROR" "$sha_path" "${workdir}/${sha_artifact}"; then
        die "could not download ${sha_artifact} from the same mirror ($CHOSEN_MIRROR); refusing to install an unverified tarball"
    fi
    verify_sha256_sidecar "$workdir" "$sha_artifact"
    if [ -n "$SHA256_OVERRIDE" ]; then
        verify_sha256_value "$tarball_file" "$SHA256_OVERRIDE"
    fi
    extract_tarball "$tarball_file" "$staging"
    STAGING_ROOT="$(staging_root "$staging" "$tarball_file")"
    BINARY_ROOT="$STAGING_ROOT"
    validate_staging "$STAGING_ROOT"
}

# --- source-build fallback --------------------------------------------------
# Builds the three binaries from the tagged source tarball. This is
# the fallback path only; the release tarball is the primary path.
# Both the Go toolchain tarball and the source tarball are SHA-256
# verified against caller-supplied hashes; the script fails closed
# when a required hash is absent.

go_is_usable() {
    local ver major minor
    command -v go >/dev/null 2>&1 || return 1
    ver="$(go version 2>/dev/null | awk '{print $3}')"
    ver="${ver#go}"
    major="${ver%%.*}"
    minor="${ver#*.}"
    minor="${minor%%.*}"
    [ "$major" -gt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -ge 26 ]; }
}

bootstrap_go_toolchain() {
    local cache_dir="$1" toolchain_file="$2" url
    local go_file
    go_file="go${GO_VERSION}.linux-$(arch_name).tar.gz"
    local candidates=(
        "https://go.dev/dl/${go_file}"
        "https://dl.google.com/go/${go_file}"
    )
    local candidate
    for candidate in "${candidates[@]}"; do
        if curl -fsSI --max-time 10 -o /dev/null "$candidate" 2>/dev/null; then
            url="$candidate"
            break
        fi
    done
    if [ -z "${url:-}" ]; then
        for base in "${MIRRORS[@]}"; do
            candidate="$(mirror_url "$base" "/go.dev/dl/${go_file}")"
            if curl -fsSI --max-time 10 -o /dev/null "$candidate" 2>/dev/null; then
                url="$candidate"
                break
            fi
        done
    fi
    [ -n "${url:-}" ] || die "could not reach any Go toolchain download location for $go_file"
    note "Downloading Go toolchain $url"
    curl -fSL --show-error --max-time 300 -o "$toolchain_file" "$url" || die "Go toolchain download failed"
    verify_sha256_value "$toolchain_file" "$GO_SHA256"
    mkdir -p "$cache_dir"
    tar -xzf "$toolchain_file" -C "$cache_dir"
    [ -x "$cache_dir/go/bin/go" ] || die "Go toolchain extraction did not produce $cache_dir/go/bin/go"
    printf '%s' "$cache_dir/go/bin"
}

acquire_from_source() {
    local arch="$1" staging="$2" workdir="$3"
    local go_bin_dir cache_dir src_tarball src_dir build_root version_ldflags
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] download the Go %s toolchain (SHA-256 verified) and the %s source tarball (SHA-256 verified), then build nexounel-server, nexounel-node, and nexounel-panel\n' "$GO_VERSION" "${RELEASE_VERSION:-<release>}"
        STAGING_ROOT="<staging>"
        return 0
    fi
    [ -n "$RELEASE_VERSION" ] || die "--build-from-source requires --release <version> (a tag name)"
    [ -n "$GO_SHA256" ] || die "--build-from-source requires --go-sha256 HASH: refusing to use an unverified toolchain"
    [ -n "$SOURCE_SHA256" ] || die "--build-from-source requires --source-sha256 HASH: refusing to build unverified source"
    if [ -n "${HOME:-}" ] && [ "$(id -u)" -eq 0 ] && [ -z "$DESTDIR" ]; then
        cache_dir="/opt/nexounel/.build"
    else
        cache_dir="${HOME:-/tmp}/.cache/nexounel"
    fi
    if go_is_usable; then
        go_bin_dir="$(dirname "$(command -v go)")"
        note "Using installed Go toolchain: $(command -v go)"
    else
        go_bin_dir="$(bootstrap_go_toolchain "$cache_dir" "${workdir}/go-toolchain.tar.gz")"
    fi
    src_tarball="${workdir}/nexounel-source.tar.gz"
    if ! download_artifact "/${REPO_OWNER}/${REPO_NAME}/archive/refs/tags/${RELEASE_VERSION}.tar.gz" "$src_tarball"; then
        die "could not download the source tarball for $RELEASE_VERSION from any mirror"
    fi
    verify_sha256_value "$src_tarball" "$SOURCE_SHA256"
    mkdir -p "$cache_dir/src"
    tar -xzf "$src_tarball" -C "$cache_dir/src"
    src_dir="$(find "$cache_dir/src" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
    [ -n "$src_dir" ] || die "source tarball extracted to an empty directory"
    [ -f "$src_dir/core/go.mod" ] || die "source tarball does not contain core/go.mod: $src_dir"
    build_root="${staging}/nexounel-${RELEASE_VERSION}-linux-${arch}"
    mkdir -p "$build_root/configs" "$build_root/units" "$build_root/logrotate"
    version_ldflags="-X github.com/MNSH-Nexo/Nexounel/core/internal/version.BuildVersion=${RELEASE_VERSION}"
    export PATH="$go_bin_dir:$PATH"
    export GOCACHE="$cache_dir/gocache"
    export GOPROXY=off
    (cd "$src_dir/core" && go build -trimpath -ldflags "$version_ldflags" -o "$build_root/nexounel-server" ./cmd/nexounel-server) || die "go build failed for nexounel-server"
    (cd "$src_dir/core" && go build -trimpath -ldflags "$version_ldflags" -o "$build_root/nexounel-node" ./cmd/nexounel-node) || die "go build failed for nexounel-node"
    (cd "$src_dir/core" && go build -trimpath -ldflags "$version_ldflags" -o "$build_root/nexounel-panel" ./cmd/nexounel-panel) || die "go build failed for nexounel-panel"
    chmod 755 "$build_root/nexounel-server" "$build_root/nexounel-node" "$build_root/nexounel-panel"
    cp -a "$src_dir/core/configs/nexounel-server.toml" "$src_dir/core/configs/nexounel-node.toml" "$src_dir/core/configs/nodes.toml.example" "$src_dir/core/configs/client_resolvers.txt" "$build_root/configs/" || die "source tarball is missing sample configs"
    if [ -d "$src_dir/install/units" ]; then
        cp -a "$src_dir/install/units/"*.service "$build_root/units/" || die "source tarball units copy failed"
        cp -a "$src_dir/install/logrotate/nexounel" "$build_root/logrotate/" || die "source tarball logrotate copy failed"
    else
        die "source tarball has no install/units; cannot build units from source for $RELEASE_VERSION"
    fi
    STAGING_ROOT="$build_root"
    BINARY_ROOT="$build_root"
    validate_staging "$STAGING_ROOT"
}

# --- post-install validation ------------------------------------------------

check_server_config() {
    local install_dir="$1"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] (cd %s && %s -config %s -check-config)\n' "$install_dir" "$install_dir/nexounel-server" "$install_dir/nexounel-server.toml"
        return 0
    fi
    (cd "$install_dir" && "$install_dir/nexounel-server" -config "$install_dir/nexounel-server.toml" -check-config) \
        || die "nexounel-server -check-config failed; services were not started. Fix $install_dir/nexounel-server.toml and re-run the installer."
    note "Server configuration validated."
}

check_node_config() {
    local config="$1"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] validate TOML syntax of %s (python3 tomllib, if available)\n' "$config"
        return 0
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import sys, tomllib; tomllib.load(open(sys.argv[1], "rb"))' "$config" \
            || die "nexounel-node.toml does not parse as TOML: $config"
        note "Node configuration parses as TOML."
    else
        note "python3 not found; skipping node TOML syntax check for $config"
    fi
}

# --- panel first-run init ---------------------------------------------------
# The panel binary owns credential creation: nexounel-panel -init
# generates the webpath token and session key and stores the hashed
# admin password in nexounel-panel.toml (0600). This script only
# prompts, invokes -init, and verifies with -check-config. It never
# writes panel credentials itself.

prompt_admin_password() {
    local first second attempt
    attempt=1
    while [ "$attempt" -le 3 ]; do
        printf 'Choose an admin password for the panel (minimum 12 characters): '
        IFS= read -r -s first || die "could not read the admin password"
        printf '\n'
        printf 'Repeat the admin password: '
        IFS= read -r -s second || die "could not read the admin password"
        printf '\n'
        if [ ${#first} -lt 12 ]; then
            warn "password is shorter than 12 characters; try again"
        elif [ "$first" != "$second" ]; then
            warn "passwords do not match; try again"
        else
            return 0
        fi
        attempt=$((attempt + 1))
    done
    die "admin password was not confirmed after 3 attempts; panel left uninitialized"
}

# Extract a simple `key = "value"` (or bare value) from a TOML file.
# Prints the value, or nothing when the key is absent. Used only for
# the post-init panel URL display; a parse failure is not fatal.
toml_string_value() {
    local file="$1" key="$2" line value
    line="$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$file" 2>/dev/null | head -n 1 || true)"
    [ -n "$line" ] || return 0
    value="${line#*=}"
    value="$(printf '%s' "$value" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"//' -e 's/"[[:space:]]*$//' -e "s/^'//" -e "s/'[[:space:]]*$//")"
    printf '%s' "$value"
}

print_panel_url() {
    local config="$1" web_path listen_addr host port display_host url
    web_path="$(toml_string_value "$config" "web_path")"
    [ -n "$web_path" ] || web_path="$(toml_string_value "$config" "webpath")"
    listen_addr="$(toml_string_value "$config" "listen_addr")"
    [ -n "$listen_addr" ] || listen_addr="$(toml_string_value "$config" "listen_address")"
    [ -n "$listen_addr" ] || listen_addr="$(toml_string_value "$config" "address")"
    if [ -z "$web_path" ] || [ -z "$listen_addr" ]; then
        note "Panel initialized. The panel URL could not be parsed from $config; read the web path and listen address there."
        return 0
    fi
    host="${listen_addr%%:*}"
    port="${listen_addr##*:}"
    display_host="$host"
    if [ "$host" = "0.0.0.0" ] || [ -z "$host" ]; then
        display_host="127.0.0.1"
    fi
    url="http://${display_host}:${port}/${web_path#/}"
    note "Panel URL (on this host): $url"
    if [ "$host" = "0.0.0.0" ]; then
        note "The panel listens on all interfaces; from another host use this host's address in place of 127.0.0.1."
    fi
}

# Runs the panel first-run init. Sets PANEL_READY=1 on success, or
# when a panel config already existed and passes -check-config.
PANEL_READY=0

init_panel() {
    local install_dir="$1" panel_bin="$2" panel_config="$3"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] prompt for the admin password (read -s, twice, min 12 chars)\n'
        printf '[dry-run] %s -init (writes %s mode 0600 with webpath, session key, hashed password)\n' "$panel_bin" "$panel_config"
        printf '[dry-run] %s -check-config\n' "$panel_bin"
        printf '[dry-run] print the panel URL from the written config\n'
        return 0
    fi
    if [ -e "$panel_config" ]; then
        note "Panel config already exists; preserving credentials in $panel_config"
        if "$panel_bin" -config "$panel_config" -check-config; then
            PANEL_READY=1
            note "Panel configuration validated."
        else
            warn "nexounel-panel -check-config failed; the panel service will not be started. Fix $panel_config or re-run with a fresh init."
        fi
        return 0
    fi
    if [ -n "$DESTDIR" ]; then
        note "DESTDIR mode: panel init skipped. After installing to the target system, run: nexounel-panel -init"
        return 0
    fi
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
        note "Non-interactive mode: no panel credentials were written."
        note "Initialize the panel manually, then enable and start it:"
        note "  nexounel-panel -init"
        note "  nexounel-panel -check-config"
        note "  systemctl enable --now nexounel-panel.service"
        return 0
    fi
    prompt_admin_password
    note "The panel will now ask for the admin password again; enter the password you just chose."
    note "Running: $panel_bin -init (from $install_dir)"
    # Run from the install directory so a default config path resolved
    # relative to the working directory lands next to the binary.
    if ! (cd "$install_dir" && "$panel_bin" -init); then
        warn "nexounel-panel -init failed; the panel service will not be started. Run 'nexounel-panel -init' manually, then enable and start nexounel-panel.service."
        return 0
    fi
    if [ -e "$panel_config" ]; then
        chmod 600 "$panel_config" || warn "could not set mode 0600 on $panel_config"
    fi
    if "$panel_bin" -config "$panel_config" -check-config; then
        PANEL_READY=1
        note "Panel configuration validated."
        print_panel_url "$panel_config"
    else
        warn "nexounel-panel -check-config failed after init; the panel service will not be started."
    fi
}

# --- install flow -----------------------------------------------------------

print_firewall_and_bind_notes() {
    if [ "$MODE_MOTHER" -eq 1 ]; then
        note ""
        note "Firewall (NOT applied by this installer; apply with your own firewall tooling):"
        note "  Mother: allow inbound UDP and TCP on port 53 (the DNS tunnel port)."
        note "  Nodes: no inbound ports are required."
        note ""
        note "Port 53 bind lesson: bind a SPECIFIC IP in nexounel-server.toml"
        note "(UDP_HOST), not 0.0.0.0. systemd-resolved owns loopback stubs"
        note "on :53 and a wildcard bind conflicts with them. The sample"
        note "config ships UDP_HOST = \"0.0.0.0\"; change it to this host's"
        note "public IP before starting the server in production."
    fi
}

do_install() {
    local arch workdir staging install_dir unit_dir logrotate_dir log_dir
    arch="$(arch_name)"
    build_mirror_list

    if [ "$DRY_RUN" -eq 0 ] && [ -z "$DESTDIR" ] && [ "$(id -u)" -ne 0 ]; then
        die "run as root to install to the system paths (or use --destdir for a test install)"
    fi
    for tool in tar sha256sum install mktemp; do
        command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
    done
    # curl is only needed for downloads. A local --tarball install
    # (including an offline bundle) and --dry-run never fetch
    # anything, so they must work on hosts without curl.
    if [ -z "$TARBALL" ] && [ "$DRY_RUN" -eq 0 ]; then
        command -v curl >/dev/null 2>&1 || die "required tool not found: curl (not required with --tarball)"
    fi
    if [ -z "$DESTDIR" ] && [ "$DRY_RUN" -eq 0 ]; then
        command -v systemctl >/dev/null 2>&1 || die "systemctl not found: this installer requires systemd"
    fi

    DESTDIR="$(strip_trailing_slash "${DESTDIR:-}")"
    install_dir="${DESTDIR}/opt/nexounel"
    unit_dir="${DESTDIR}/etc/systemd/system"
    logrotate_dir="${DESTDIR}/etc/logrotate.d"
    log_dir="${DESTDIR}/var/log/nexounel"

    workdir="$(mktemp -d)"
    staging="${workdir}/staging"
    mkdir -p "$staging"
    # Guarded: on an early failure the EXIT trap can fire after the
    # function's locals are out of scope; without the guard, `set -u`
    # turns the cleanup itself into a confusing "unbound variable"
    # error that masks the real failure.
    trap '[ -n "${workdir:-}" ] && rm -rf "$workdir"' EXIT

    STAGING_ROOT=""
    if [ -n "$TARBALL" ]; then
        acquire_from_local_tarball "$arch" "$TARBALL" "$staging"
    elif [ "$BUILD_FROM_SOURCE" -eq 1 ]; then
        acquire_from_source "$arch" "$staging" "$workdir"
    else
        acquire_from_download "$arch" "$staging" "$workdir"
    fi

    ensure_dir "$install_dir" "755"
    ensure_dir "$log_dir" "755"
    ensure_dir "$unit_dir" "755"
    ensure_dir "$logrotate_dir" "755"

    if [ "$MODE_MOTHER" -eq 1 ]; then
        install_file "$BINARY_ROOT/nexounel-server" "$install_dir/nexounel-server" "755"
        install_file "$BINARY_ROOT/nexounel-panel" "$install_dir/nexounel-panel" "755"
        install_config_if_absent "$STAGING_ROOT/configs/nexounel-server.toml" "$install_dir/nexounel-server.toml" "600"
        install_config_if_absent "$STAGING_ROOT/configs/nodes.toml.example" "$install_dir/nodes.toml" "600"
        install_file "$STAGING_ROOT/units/nexounel.service" "$unit_dir/nexounel.service" "644"
        install_file "$STAGING_ROOT/units/nexounel-panel.service" "$unit_dir/nexounel-panel.service" "644"
    fi
    if [ "$MODE_NODE" -eq 1 ]; then
        install_file "$BINARY_ROOT/nexounel-node" "$install_dir/nexounel-node" "755"
        install_config_if_absent "$STAGING_ROOT/configs/nexounel-node.toml" "$install_dir/nexounel-node.toml" "600"
        install_file "$STAGING_ROOT/units/nexounel-node.service" "$unit_dir/nexounel-node.service" "644"
    fi
    install_config_if_absent "$STAGING_ROOT/configs/client_resolvers.txt" "$install_dir/client_resolvers.txt" "644"
    install_file "$STAGING_ROOT/logrotate/nexounel" "$logrotate_dir/nexounel" "644"

    run_systemctl daemon-reload

    if [ "$MODE_MOTHER" -eq 1 ]; then
        check_server_config "$install_dir"
    fi
    if [ "$MODE_NODE" -eq 1 ]; then
        check_node_config "$install_dir/nexounel-node.toml"
    fi

    if [ "$MODE_MOTHER" -eq 1 ]; then
        init_panel "$install_dir" "$install_dir/nexounel-panel" "$install_dir/nexounel-panel.toml"
    fi

    if [ "$MODE_MOTHER" -eq 1 ]; then
        run_systemctl enable nexounel.service
        run_systemctl start nexounel.service
        if [ "$PANEL_READY" -eq 1 ]; then
            run_systemctl enable nexounel-panel.service
            run_systemctl start nexounel-panel.service
        elif [ "$DRY_RUN" -eq 1 ]; then
            printf '[dry-run] systemctl enable/start nexounel-panel.service (only after panel init succeeds)\n'
        else
            note "Panel service left disabled: the panel is not initialized (see the init notes above)."
        fi
    fi
    if [ "$MODE_NODE" -eq 1 ]; then
        run_systemctl enable nexounel-node.service
        run_systemctl start nexounel-node.service
    fi

    print_firewall_and_bind_notes
    note ""
    note "Install complete: $install_dir"
    if [ "$MODE_MOTHER" -eq 1 ] && [ "$PANEL_READY" -eq 0 ] && [ "$DRY_RUN" -eq 0 ] && [ -z "$DESTDIR" ] && [ "$NON_INTERACTIVE" -eq 1 ]; then
        note "Panel is uninitialized (non-interactive install). Run 'nexounel-panel -init' as root, then 'systemctl enable --now nexounel-panel.service'."
    fi
    trap - EXIT
    rm -rf "$workdir"
}

# --- uninstall flow ---------------------------------------------------------
# Removes only Nexounel's own files: binaries, units, and the
# logrotate file. Configs and keys are deleted only on explicit
# confirmation (default NO); --non-interactive always preserves them.
# Nothing outside the install root, the unit directory, and the
# logrotate file is ever touched. Logs in /var/log/nexounel are left
# in place.

remove_file() {
    local file="$1"
    if [ ! -e "$file" ]; then
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] rm %s\n' "$file"
        return 0
    fi
    rm -f "$file"
    note "Removed: $file"
}

do_uninstall() {
    local install_dir unit_dir logrotate_dir
    local unit answer config_file
    local -a removed_units=() preserved=() removed_configs=()
    DESTDIR="$(strip_trailing_slash "${DESTDIR:-}")"
    install_dir="${DESTDIR}/opt/nexounel"
    unit_dir="${DESTDIR}/etc/systemd/system"
    logrotate_dir="${DESTDIR}/etc/logrotate.d"

    for unit in nexounel.service nexounel-node.service nexounel-panel.service; do
        if [ -e "$unit_dir/$unit" ]; then
            removed_units+=("$unit")
            if [ "$DRY_RUN" -eq 1 ]; then
                printf '[dry-run] systemctl stop %s\n' "$unit"
                printf '[dry-run] systemctl disable %s\n' "$unit"
            elif [ -n "$DESTDIR" ]; then
                printf 'DESTDIR mode: systemctl skipped: systemctl stop %s\n' "$unit"
                printf 'DESTDIR mode: systemctl skipped: systemctl disable %s\n' "$unit"
            else
                command systemctl stop "$unit" 2>/dev/null || warn "could not stop $unit (it may not have been running)"
                command systemctl disable "$unit" 2>/dev/null || warn "could not disable $unit"
            fi
        fi
    done

    remove_file "$install_dir/nexounel-server"
    remove_file "$install_dir/nexounel-node"
    remove_file "$install_dir/nexounel-panel"
    remove_file "$unit_dir/nexounel.service"
    remove_file "$unit_dir/nexounel-node.service"
    remove_file "$unit_dir/nexounel-panel.service"
    remove_file "$logrotate_dir/nexounel"
    if [ -n "$DESTDIR" ]; then
        printf 'DESTDIR mode: systemctl skipped: systemctl daemon-reload\n'
    elif [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] systemctl daemon-reload\n'
    else
        command systemctl daemon-reload 2>/dev/null || warn "systemctl daemon-reload failed"
    fi

    # Configs and keys: ask once, default NO. Non-interactive and
    # dry-run (without an answer) preserve them.
    answer="n"
    if [ "$NON_INTERACTIVE" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
        printf 'Delete configuration and key files in %s (nexounel-*.toml, nodes.toml, *.key)? [y/N] ' "$install_dir"
        IFS= read -r answer || answer="n"
    elif [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] ask before deleting configs that hold keys (default NO); with --non-interactive configs are preserved\n'
    fi
    case "$answer" in
        y|Y|yes|YES)
            for config_file in "$install_dir"/nexounel-server.toml "$install_dir"/nexounel-node.toml "$install_dir"/nexounel-panel.toml "$install_dir"/nodes.toml "$install_dir"/nodes.toml.example "$install_dir"/client_resolvers.txt; do
                if [ -e "$config_file" ]; then
                    removed_configs+=("$config_file")
                    remove_file "$config_file"
                fi
            done
            for config_file in "$install_dir"/*.key; do
                [ -e "$config_file" ] || continue
                removed_configs+=("$config_file")
                remove_file "$config_file"
            done
            ;;
        *)
            for config_file in "$install_dir"/nexounel-server.toml "$install_dir"/nexounel-node.toml "$install_dir"/nexounel-panel.toml "$install_dir"/nodes.toml "$install_dir"/nodes.toml.example "$install_dir"/client_resolvers.txt; do
                [ -e "$config_file" ] && preserved+=("$config_file")
            done
            for config_file in "$install_dir"/*.key; do
                [ -e "$config_file" ] || continue
                preserved+=("$config_file")
            done
            note "Preserved configs/keys in $install_dir (uninstall never deletes them without confirmation)."
            ;;
    esac

    if [ "$DRY_RUN" -eq 0 ] && [ -d "$install_dir" ]; then
        rmdir "$install_dir" 2>/dev/null || true
    fi

    note "Uninstall complete."
    if [ "${#removed_units[@]}" -gt 0 ]; then
        note "Stopped/disabled units: ${removed_units[*]}"
    else
        note "No Nexounel units were present."
    fi
    if [ "${#removed_configs[@]}" -gt 0 ]; then
        note "Removed configs: ${removed_configs[*]}"
    fi
    if [ "${#preserved[@]}" -gt 0 ]; then
        note "Preserved: ${preserved[*]}"
    fi
    note "Logs in ${DESTDIR}/var/log/nexounel were left in place."
}

# --- main -------------------------------------------------------------------

main() {
    parse_args "$@"
    if [ "$DO_UNINSTALL" -eq 1 ]; then
        if [ "$MODE_MOTHER" -eq 1 ] || [ "$MODE_NODE" -eq 1 ]; then
            die "--uninstall cannot be combined with --mother/--node"
        fi
        if [ -n "$TARBALL" ] || [ "$BUILD_FROM_SOURCE" -eq 1 ]; then
            die "--uninstall cannot be combined with --tarball/--build-from-source"
        fi
        do_uninstall
        exit 0
    fi
    if [ "$MODE_MOTHER" -eq 0 ] && [ "$MODE_NODE" -eq 0 ]; then
        printf 'error: neither --mother nor --node given\n' >&2
        usage >&2
        exit 2
    fi
    do_install
}

main "$@"
