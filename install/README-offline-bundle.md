# Nexounel offline bundle

A single self-contained download for servers without reliable network
access or working mirrors/package sources. Everything needed to
install is inside this bundle; installing from it downloads nothing.

## Contents

| Path | Contents |
| --- | --- |
| `install.sh` | The installer (same as `install/install.sh`) |
| `SHA256SUMS` | SHA-256 of every binary in the bundle |
| `linux-amd64/` | `nexounel-server`, `nexounel-node`, `nexounel-panel` for amd64 |
| `linux-arm64/` | The same three binaries for arm64 |
| `configs/` | Sample configs and the default resolver list |
| `units/` | systemd units |
| `logrotate/` | Logrotate config |

## Install (offline)

Keep the `.tar.gz` and its `.sha256` sidecar next to the extracted
directory: the installer verifies the whole bundle against the sidecar
automatically, then verifies the selected binaries against the
bundle's `SHA256SUMS`. No network access is used at any point, and
`curl` is not required.

```sh
tar -xzf nexounel-<version>-offline.tar.gz
cd nexounel-<version>-offline

# Mother (server + panel), interactive first-run panel init:
sudo ./install.sh --mother --tarball ../nexounel-<version>-offline.tar.gz

# Node, no prompts (panel init is a mother-only step):
sudo ./install.sh --node --tarball ../nexounel-<version>-offline.tar.gz --non-interactive

# Both roles on one host (lab use):
sudo ./install.sh --mother --node --tarball ../nexounel-<version>-offline.tar.gz --non-interactive
```

The host architecture (amd64 or arm64) is detected automatically and
the matching binaries are installed; any other architecture fails
loudly instead of installing the wrong binaries. Re-running the
installer upgrades the binaries and preserves existing configs, keys,
the node registry, and panel credentials.

Verify the bundle before installing (optional; the installer verifies
it again):

```sh
sha256sum -c nexounel-<version>-offline.tar.gz.sha256
```

## Uninstall

```sh
sudo ./install.sh --uninstall
```

Stops and disables the units, removes binaries, units, and the
logrotate file, and asks (default NO) before deleting configs that
hold keys. `--non-interactive` always preserves configs.

## Notes

- Bind a specific IP in `nexounel-server.toml` (`UDP_HOST`), not
  `0.0.0.0`: systemd-resolved owns loopback stubs on :53 and a
  wildcard bind conflicts with them.
- Firewall rules are NOT applied by the installer. The mother needs
  inbound UDP/TCP 53; nodes need nothing inbound.
- For servers with working network access, the one-command mirror
  install is simpler; see `docs/OFFLINE-INSTALL.md` in the repository
  for both paths.

---

## شروع سریع (فارسی)

این بسته برای سرورهایی است که به اینترنت یا میرورها دسترسی ندارند.
همه‌ی فایل‌های لازم داخل همین بسته است و نصب هیچ دانلودی انجام
نمی‌دهد.

```sh
tar -xzf nexounel-<version>-offline.tar.gz
cd nexounel-<version>-offline

# سرور مادر (سرور + پنل):
sudo ./install.sh --mother --tarball ../nexounel-<version>-offline.tar.gz

# نود (بدون سؤال):
sudo ./install.sh --node --tarball ../nexounel-<version>-offline.tar.gz --non-interactive
```

معماری سرور (amd64 یا arm64) به‌صورت خودکار تشخیص داده می‌شود و
فایل‌های درست نصب می‌شوند. نصب دوباره، فایل‌های اجرایی را به‌روز
می‌کند و تنظیمات، کلیدها و اطلاعات پنل را حفظ می‌کند.

حذف نصب:

```sh
sudo ./install.sh --uninstall
```
