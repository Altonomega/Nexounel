#!/usr/bin/env bash
# Installer tests: offline bundle build, fully-offline install proof,
# architecture selection, checksum refusal, and install/uninstall
# round-trips.
#
# Run from the repository root (or anywhere; REPO_ROOT defaults to the
# parent of this script's directory and can be overridden):
#   bash install/test-install.sh [REPO_ROOT]
#
# Requires: bash, go 1.26+ (for the bundle/release builds), tar,
# sha256sum, coreutils. unshare + strace enable the strongest offline
# proof; when either is absent the network-namespace/strace part is
# skipped with a visible note, but the no-curl-PATH and trap-binary
# assertions still run. shellcheck is run when available.
#
# Everything runs in a temporary directory; nothing touches the host
# system (all installs use --destdir). The script exits non-zero when
# any case fails and prints a summary.
#
# Note: the suite builds and extracts several ~100MB trees (bundle +
# release tarball + extractions). When /tmp is a small tmpfs, point
# TMPDIR at a directory on a larger disk before running.

set -uo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
[ -n "${1:-}" ] && REPO_ROOT="$1"
[ -f "$REPO_ROOT/core/go.mod" ] || { printf 'error: REPO_ROOT does not look like the Nexounel repo: %s\n' "$REPO_ROOT" >&2; exit 2; }

export PATH="$HOME/workspace/tools/go-1.26.10/bin:$PATH"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

PASS=0
FAIL=0
FAILED_CASES=()

pass() {
    PASS=$((PASS + 1))
    printf 'ok   %s\n' "$1"
}

fail() {
    FAIL=$((FAIL + 1))
    FAILED_CASES+=("$1")
    printf 'FAIL %s\n' "$1"
}

check_file() { # check_file <name> <path>
    if [ -e "$2" ]; then pass "$1"; else fail "$1 (missing: $2)"; fi
}

check_grep() { # check_grep <name> <pattern> <file>
    if grep -q "$2" "$3" 2>/dev/null; then pass "$1"; else fail "$1 (pattern '$2' not found in $3)"; fi
}

check_no_grep() { # check_no_grep <name> <pattern> <file>
    if [ -e "$3" ] && grep -q "$2" "$3" 2>/dev/null; then fail "$1 (pattern '$2' unexpectedly found in $3)"; else pass "$1"; fi
}

# expect_fail_with <name> <exit-code> <pattern> <logfile>: pass when the
# command failed and the log contains the pattern.
expect_fail_with() {
    if [ "$2" -ne 0 ] && grep -q "$3" "$4" 2>/dev/null; then
        pass "$1"
    else
        fail "$1 (exit $2)"
        tail -10 "$4"
    fi
}

# machine_of <elf-file>: print the ELF e_machine value (62 = x86-64,
# 183 = AArch64) using od on the ELF header.
machine_of() {
    od -An -j 18 -N 2 -tu2 "$1" 2>/dev/null | tr -d ' '
}

# mk_uname_stub <dir> <value>: write an executable `uname` that always
# prints <value> (the installer only ever calls `uname -m`).
mk_uname_stub() {
    printf '#!/bin/sh\nprintf "%%s\\n" "%s"\n' "$2" >"$1/uname"
    chmod +x "$1/uname"
}

# build_minbin <dir>: symlinks to the tools the installer needs, plus
# trap stubs for curl/wget/systemctl that log any invocation and fail.
# The trap log path is $T/trap.log (shared, reset by callers).
build_minbin() {
    local dir="$1" tool
    mkdir -p "$dir"
    for tool in bash sh env tar gzip sha256sum install mktemp grep awk sed date cp mkdir chmod rm head sort tr uname id python3 basename cat ls; do
        ln -sf "$(command -v "$tool")" "$dir/$tool"
    done
    for tool in curl wget systemctl; do
        printf '#!/bin/sh\necho "TRAP-CALLED: %s $@" >> "%s/trap.log"\nexit 1\n' "$tool" "$T" >"$dir/$tool"
        chmod +x "$dir/$tool"
    done
}

printf '== setup: building offline bundle and release tarball ==\n'
command -v go >/dev/null 2>&1 || { printf 'error: go toolchain not found on PATH\n' >&2; exit 2; }
"$REPO_ROOT/install/package-offline-bundle.sh" --version test-offline-1 --out "$T/dist" >"$T/bundle-build.log" 2>&1 \
    || { printf 'error: package-offline-bundle.sh failed; see %s\n' "$T/bundle-build.log" >&2; tail -20 "$T/bundle-build.log" >&2; exit 2; }
"$REPO_ROOT/install/package-release.sh" --version test-rel-1 --out "$T/dist" >"$T/release-build.log" 2>&1 \
    || { printf 'error: package-release.sh failed; see %s\n' "$T/release-build.log" >&2; tail -20 "$T/release-build.log" >&2; exit 2; }

BUNDLE_TAR="$T/dist/nexounel-test-offline-1-offline.tar.gz"
RELEASE_TAR="$T/dist/nexounel-test-rel-1-linux-amd64.tar.gz"
TOP="nexounel-test-offline-1-offline"

printf '== case: bundle layout ==\n'
check_file "bundle tarball exists" "$BUNDLE_TAR"
check_file "bundle .sha256 sidecar exists" "${BUNDLE_TAR}.sha256"
if (cd "$T/dist" && sha256sum -c "nexounel-test-offline-1-offline.tar.gz.sha256" >/dev/null 2>&1); then
    pass "bundle sidecar verifies"
else
    fail "bundle sidecar verifies"
fi
tar -tzf "$BUNDLE_TAR" | grep -v '/$' | LC_ALL=C sort >"$T/bundle-files.txt"
cat >"$T/bundle-files.expected" <<EOF
$TOP/README.md
$TOP/SHA256SUMS
$TOP/configs/client_resolvers.txt
$TOP/configs/nexounel-node.toml
$TOP/configs/nexounel-server.toml
$TOP/configs/nodes.toml.example
$TOP/install.sh
$TOP/linux-amd64/nexounel-node
$TOP/linux-amd64/nexounel-panel
$TOP/linux-amd64/nexounel-server
$TOP/linux-arm64/nexounel-node
$TOP/linux-arm64/nexounel-panel
$TOP/linux-arm64/nexounel-server
$TOP/logrotate/nexounel
$TOP/units/nexounel-node.service
$TOP/units/nexounel-panel.service
$TOP/units/nexounel.service
EOF
if cmp -s "$T/bundle-files.txt" "$T/bundle-files.expected"; then
    pass "bundle file list is exactly the expected set"
else
    fail "bundle file list is exactly the expected set"
    diff "$T/bundle-files.expected" "$T/bundle-files.txt" | head -20
fi
mkdir -p "$T/extract"
tar -xzf "$BUNDLE_TAR" -C "$T/extract"
if (cd "$T/extract/$TOP" && sha256sum -c SHA256SUMS >/dev/null 2>&1); then
    pass "bundle SHA256SUMS verifies after extraction"
else
    fail "bundle SHA256SUMS verifies after extraction"
fi
check_grep "bundle README has Persian quick-start" "شروع سریع" "$T/extract/$TOP/README.md"

printf '== case: offline install proof (no network, no curl) ==\n'
build_minbin "$T/minbin"
rm -f "$T/trap.log"
PROOF_DEST="$T/proof-dest"
mkdir -p "$PROOF_DEST"
PROOF_CMD=(env "PATH=$T/minbin" "$T/extract/$TOP/install.sh" --mother --node --tarball "$BUNDLE_TAR" --destdir "$PROOF_DEST" --non-interactive)
if command -v unshare >/dev/null 2>&1 && command -v strace >/dev/null 2>&1; then
    printf 'proof method: unshare -n + strace -f -e trace=%%network + no-curl PATH + trap binaries\n'
    unshare -n strace -f -e trace=%network -o "$T/strace.log" "${PROOF_CMD[@]}" >"$T/proof.log" 2>&1
    PROOF_EXIT=$?
    check_no_grep "strace shows no AF_INET/AF_INET6 activity" "AF_INET" "$T/strace.log"
else
    printf 'proof method: REDUCED (unshare or strace missing) — no-curl PATH + trap binaries only\n'
    "${PROOF_CMD[@]}" >"$T/proof.log" 2>&1
    PROOF_EXIT=$?
fi
if [ "$PROOF_EXIT" -eq 0 ]; then pass "offline install exits 0"; else fail "offline install exits 0 (got $PROOF_EXIT)"; tail -20 "$T/proof.log"; fi
if [ ! -e "$T/trap.log" ]; then pass "curl/wget/systemctl never invoked"; else fail "curl/wget/systemctl never invoked"; cat "$T/trap.log"; fi
check_grep "installer verified bundle SHA256SUMS" "Offline bundle: SHA256SUMS verified" "$T/proof.log"
check_file "server binary installed" "$PROOF_DEST/opt/nexounel/nexounel-server"
check_file "node binary installed" "$PROOF_DEST/opt/nexounel/nexounel-node"
check_file "panel binary installed" "$PROOF_DEST/opt/nexounel/nexounel-panel"
if [ "$(machine_of "$PROOF_DEST/opt/nexounel/nexounel-server")" = "62" ]; then
    pass "installed server binary is amd64 (e_machine 62)"
else
    fail "installed server binary is amd64 (e_machine 62)"
fi
if "$PROOF_DEST/opt/nexounel/nexounel-server" -version 2>&1 | grep -q "test-offline-1"; then
    pass "installed server reports bundle version"
else
    fail "installed server reports bundle version"
fi
check_file "server unit installed" "$PROOF_DEST/etc/systemd/system/nexounel.service"
check_file "node unit installed" "$PROOF_DEST/etc/systemd/system/nexounel-node.service"
check_file "panel unit installed" "$PROOF_DEST/etc/systemd/system/nexounel-panel.service"
check_file "logrotate installed" "$PROOF_DEST/etc/logrotate.d/nexounel"
check_file "server sample config installed" "$PROOF_DEST/opt/nexounel/nexounel-server.toml"
check_file "node sample config installed" "$PROOF_DEST/opt/nexounel/nexounel-node.toml"
check_file "resolver list installed" "$PROOF_DEST/opt/nexounel/client_resolvers.txt"
if [ ! -e "$PROOF_DEST/opt/nexounel/nexounel-panel.toml" ]; then
    pass "panel config not created in DESTDIR mode (init skipped)"
else
    fail "panel config not created in DESTDIR mode (init skipped)"
fi

printf '== case: plain release tarball still installs (backward compat) ==\n'
REL_DEST="$T/rel-dest"
mkdir -p "$REL_DEST"
REL_SHA="$(sha256sum "$RELEASE_TAR" | awk '{print $1}')"
"$REPO_ROOT/install/install.sh" --mother --node --tarball "$RELEASE_TAR" --sha256 "$REL_SHA" --destdir "$REL_DEST" --non-interactive >"$T/rel.log" 2>&1
REL_EXIT=$?
if [ "$REL_EXIT" -eq 0 ]; then
    pass "release-tarball install exits 0"
else
    fail "release-tarball install exits 0"
    tail -10 "$T/rel.log"
fi
check_file "release install: server binary" "$REL_DEST/opt/nexounel/nexounel-server"
if [ "$(machine_of "$REL_DEST/opt/nexounel/nexounel-server")" = "62" ]; then
    pass "release install: binary is amd64"
else
    fail "release install: binary is amd64"
fi

printf '== case: wrong architecture fails loudly ==\n'
mkdir -p "$T/fake-riscv"
mk_uname_stub "$T/fake-riscv" "riscv64"
BUNDLE_SHA="$(sha256sum "$BUNDLE_TAR" | awk '{print $1}')"
PATH="$T/fake-riscv:/usr/bin:/bin" "$REPO_ROOT/install/install.sh" --mother --tarball "$BUNDLE_TAR" --sha256 "$BUNDLE_SHA" --destdir "$T/riscv-dest" --non-interactive >"$T/riscv.log" 2>&1
RISCV_EXIT=$?
expect_fail_with "unknown arch dies with 'unsupported architecture'" "$RISCV_EXIT" "unsupported architecture: riscv64" "$T/riscv.log"
# Bundle with the arm64 directory removed + faked aarch64: must fail
# on the missing arch dir, never install amd64 binaries.
mkdir -p "$T/noarm64"
tar -xzf "$BUNDLE_TAR" -C "$T/noarm64"
rm -rf "$T/noarm64/$TOP/linux-arm64"
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -cf - -C "$T/noarm64" "$TOP" | gzip -n >"$T/noarm64.tar.gz"
NOARM_SHA="$(sha256sum "$T/noarm64.tar.gz" | awk '{print $1}')"
mkdir -p "$T/fake-arm"
mk_uname_stub "$T/fake-arm" "aarch64"
PATH="$T/fake-arm:/usr/bin:/bin" "$REPO_ROOT/install/install.sh" --node --tarball "$T/noarm64.tar.gz" --sha256 "$NOARM_SHA" --destdir "$T/noarm64-dest" --non-interactive >"$T/noarm64.log" 2>&1
NOARM_EXIT=$?
expect_fail_with "bundle without this arch dies loudly" "$NOARM_EXIT" "has no binaries for this architecture (arm64)" "$T/noarm64.log"
if [ ! -e "$T/noarm64-dest/opt/nexounel/nexounel-node" ]; then
    pass "no binary installed on arch-mismatch failure"
else
    fail "no binary installed on arch-mismatch failure"
fi

printf '== case: arm64 selection via faked uname ==\n'
ARM_DEST="$T/arm-dest"
mkdir -p "$ARM_DEST"
# Note: --node only. --mother would run nexounel-server -check-config,
# which cannot execute an arm64 binary on this amd64 host.
PATH="$T/fake-arm:/usr/bin:/bin" "$REPO_ROOT/install/install.sh" --node --tarball "$BUNDLE_TAR" --destdir "$ARM_DEST" --non-interactive >"$T/arm.log" 2>&1
ARM_EXIT=$?
if [ "$ARM_EXIT" -eq 0 ]; then
    pass "arm64 faked install exits 0"
else
    fail "arm64 faked install exits 0"
    tail -10 "$T/arm.log"
fi
if [ "$(machine_of "$ARM_DEST/opt/nexounel/nexounel-node")" = "183" ]; then
    pass "installed node binary is arm64 (e_machine 183)"
else
    fail "installed node binary is arm64 (e_machine 183)"
fi

printf '== case: checksum mismatch refuses ==\n'
"$REPO_ROOT/install/install.sh" --mother --tarball "$BUNDLE_TAR" --sha256 "0000000000000000000000000000000000000000000000000000000000000000" --destdir "$T/badsha-dest" --non-interactive >"$T/badsha.log" 2>&1
BADSHA_EXIT=$?
expect_fail_with "wrong --sha256 refuses" "$BADSHA_EXIT" "SHA-256 mismatch" "$T/badsha.log"
# Tampered binary inside a re-packed bundle with a correct
# whole-tarball hash: the bundle SHA256SUMS check must refuse.
mkdir -p "$T/tampered"
tar -xzf "$BUNDLE_TAR" -C "$T/tampered"
printf 'X' | dd of="$T/tampered/$TOP/linux-amd64/nexounel-server" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -cf - -C "$T/tampered" "$TOP" | gzip -n >"$T/tampered.tar.gz"
TAMP_SHA="$(sha256sum "$T/tampered.tar.gz" | awk '{print $1}')"
"$REPO_ROOT/install/install.sh" --mother --tarball "$T/tampered.tar.gz" --sha256 "$TAMP_SHA" --destdir "$T/tampered-dest" --non-interactive >"$T/tampered.log" 2>&1
TAMP_EXIT=$?
expect_fail_with "tampered binary refused by SHA256SUMS" "$TAMP_EXIT" "SHA256SUMS verification failed" "$T/tampered.log"
if [ ! -e "$T/tampered-dest/opt/nexounel/nexounel-server" ]; then
    pass "no binary installed on checksum failure"
else
    fail "no binary installed on checksum failure"
fi

printf '== case: install/uninstall round-trip preserves pre-seeded config ==\n'
RT_DEST="$T/rt-dest"
mkdir -p "$RT_DEST/opt/nexounel"
# Pre-seed a VALID server config (the bundle sample plus a sentinel
# comment): the installer preserves existing configs and then runs
# nexounel-server -check-config against them, so a sentinel-only
# file would correctly fail validation. The sentinel comment proves
# the file itself was preserved byte-for-byte.
cp "$T/extract/$TOP/configs/nexounel-server.toml" "$RT_DEST/opt/nexounel/nexounel-server.toml"
printf '# sentinel config — must survive install and uninstall\n' >>"$RT_DEST/opt/nexounel/nexounel-server.toml"
printf 'sentinel-key\n' >"$RT_DEST/opt/nexounel/node.key"
RT_SHA="$(sha256sum "$BUNDLE_TAR" | awk '{print $1}')"
"$REPO_ROOT/install/install.sh" --mother --node --tarball "$BUNDLE_TAR" --sha256 "$RT_SHA" --destdir "$RT_DEST" --non-interactive >"$T/rt-install.log" 2>&1
RT_EXIT=$?
if [ "$RT_EXIT" -eq 0 ]; then
    pass "round-trip install exits 0"
else
    fail "round-trip install exits 0"
    tail -10 "$T/rt-install.log"
fi
check_grep "pre-seeded config preserved on install" "sentinel config" "$RT_DEST/opt/nexounel/nexounel-server.toml"
check_file "pre-seeded key preserved on install" "$RT_DEST/opt/nexounel/node.key"
"$REPO_ROOT/install/install.sh" --uninstall --non-interactive --destdir "$RT_DEST" >"$T/rt-uninstall.log" 2>&1
RTU_EXIT=$?
if [ "$RTU_EXIT" -eq 0 ]; then
    pass "round-trip uninstall exits 0"
else
    fail "round-trip uninstall exits 0"
    tail -10 "$T/rt-uninstall.log"
fi
if [ ! -e "$RT_DEST/opt/nexounel/nexounel-server" ] && [ ! -e "$RT_DEST/opt/nexounel/nexounel-node" ]; then
    pass "binaries removed by uninstall"
else
    fail "binaries removed by uninstall"
fi
if [ ! -e "$RT_DEST/etc/systemd/system/nexounel.service" ] && [ ! -e "$RT_DEST/etc/logrotate.d/nexounel" ]; then
    pass "units and logrotate removed by uninstall"
else
    fail "units and logrotate removed by uninstall"
fi
check_grep "pre-seeded config preserved on uninstall" "sentinel config" "$RT_DEST/opt/nexounel/nexounel-server.toml"
check_file "pre-seeded key preserved on uninstall" "$RT_DEST/opt/nexounel/node.key"

printf '== case: smoke (help/version/dry-run) ==\n'
if "$REPO_ROOT/install/install.sh" --help >/dev/null 2>&1; then
    pass "--help exits 0"
else
    fail "--help exits 0"
fi
if "$REPO_ROOT/install/install.sh" --version 2>&1 | grep -q "nexounel-installer"; then
    pass "--version prints name"
else
    fail "--version prints name"
fi
if "$REPO_ROOT/install/install.sh" --dry-run --mother --node >/dev/null 2>&1; then
    pass "--dry-run exits 0"
else
    fail "--dry-run exits 0"
fi

printf '== case: shellcheck ==\n'
if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck -x "$REPO_ROOT/install/install.sh" "$REPO_ROOT/install/package-release.sh" "$REPO_ROOT/install/package-offline-bundle.sh" "$REPO_ROOT/install/test-install.sh"; then
        pass "shellcheck clean on installer + packaging + tests"
    else
        fail "shellcheck clean on installer + packaging + tests"
    fi
else
    printf 'SKIP shellcheck not on PATH\n'
fi

printf '\n== summary: %s passed, %s failed ==\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf 'failed cases:\n'
    printf '  - %s\n' "${FAILED_CASES[@]}"
    exit 1
fi
exit 0
