package panel

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Altonomega/Nexounel/core/internal/compression"
	"github.com/Altonomega/Nexounel/core/internal/config"
)

// Compression settings editing.
//
// The settings live as three TOML keys (ZSTD_DICT_ENABLED, ZSTD_LEVEL,
// ZSTD_LONG_ENABLED) in two config files the panel does not own: the
// server config and the node config. A map round-trip through the
// config loaders would drop comments, ordering and unknown fields, so
// the edit here is deliberately line-based: only lines assigning one
// of the managed keys are touched (their value token is replaced,
// trailing comments preserved); every other byte of the file is
// preserved verbatim. Missing keys are appended. The edited content
// is validated by reloading it with the real config loader before
// anything is installed, and the previous file is preserved as a
// .bak next to it. A failed edit never replaces a working config.
//
// The node file carries two more managed keys:
// UPLOAD_COMPRESSION_TYPE and DOWNLOAD_COMPRESSION_TYPE. The
// dictionary settings only affect zstd frames (type 1), while the
// presets default both negotiated types to LZ4 (type 2) — so
// writing the ZSTD_* keys alone leaves sessions negotiating LZ4
// and the dictionaries configured but inert on the wire. The node
// edit therefore derives both type keys from the resolved
// DictEnabled value: 1 when dictionaries are enabled, 2 (the
// documented default) when they are disabled. The server config
// has no singular compression-type keys — it negotiates through
// SUPPORTED_UPLOAD/DOWNLOAD_COMPRESSION_TYPES lists, which default
// to all types — so no type keys are written to the server file;
// instead, enabling dictionaries is refused if the server's
// resolved SUPPORTED_* lists exclude zstd, because the dictionaries
// could not engage under such a mask.
//
// The panel compression control owns all five keys on the node
// file as one bundle: applying it replaces a hand-set custom type
// (0/3) with the derived value (1 on enable, 2 on disable). The
// previous file is preserved as .bak, so a hand-set value is
// recoverable; operators who hand-tune the type keys should
// re-apply them after using the panel control, or not use the
// control for level-only tweaks.

// CompressionSettings is one side's zstd settings. Level 0 keeps the
// legacy SpeedFastest encoder; 1..22 selects an explicit zstd level.
type CompressionSettings struct {
	DictEnabled bool
	Level       int
	LongEnabled bool
}

func (s CompressionSettings) validate() error {
	if s.Level < 0 || s.Level > 22 {
		return fmt.Errorf("invalid ZSTD_LEVEL %d: must be between 0 and 22", s.Level)
	}
	return nil
}

func (s CompressionSettings) values() map[string]string {
	return map[string]string{
		"ZSTD_DICT_ENABLED": strconv.FormatBool(s.DictEnabled),
		"ZSTD_LEVEL":        strconv.Itoa(s.Level),
		"ZSTD_LONG_ENABLED": strconv.FormatBool(s.LongEnabled),
	}
}

// zstdKeyOrder is the fixed append order for the ZSTD_* keys.
var zstdKeyOrder = []string{"ZSTD_DICT_ENABLED", "ZSTD_LEVEL", "ZSTD_LONG_ENABLED"}

// typeKeyOrder is the fixed append order for the negotiated
// compression-type keys, after the ZSTD_* keys.
var typeKeyOrder = []string{"UPLOAD_COMPRESSION_TYPE", "DOWNLOAD_COMPRESSION_TYPE"}

// typeValues returns the negotiated compression types derived from
// DictEnabled: ZSTD (1) when dictionaries are enabled, LZ4 (2, the
// documented default) when they are disabled. Dictionary settings
// only affect zstd frames, so the type switch is what engages them.
func (s CompressionSettings) typeValues() map[string]string {
	t := strconv.Itoa(compression.TypeLZ4)
	if s.DictEnabled {
		t = strconv.Itoa(compression.TypeZSTD)
	}
	return map[string]string{
		"UPLOAD_COMPRESSION_TYPE":   t,
		"DOWNLOAD_COMPRESSION_TYPE": t,
	}
}

// CompressionSettingsUpdate is a partial settings change: a nil field
// keeps that file's current value. The UI form always sends all three;
// the API may send any subset.
type CompressionSettingsUpdate struct {
	DictEnabled *bool
	Level       *int
	LongEnabled *bool
}

func (u CompressionSettingsUpdate) resolve(current CompressionSettings) (CompressionSettings, error) {
	resolved := current
	if u.DictEnabled != nil {
		resolved.DictEnabled = *u.DictEnabled
	}
	if u.Level != nil {
		resolved.Level = *u.Level
	}
	if u.LongEnabled != nil {
		resolved.LongEnabled = *u.LongEnabled
	}
	return resolved, resolved.validate()
}

// editCompressionLines returns data with the three ZSTD_* key lines
// replaced (or appended when absent). All other lines are returned
// byte-identical, including comments, blank lines and line endings.
// Lines inside a TOML table section are left alone: the server/node
// configs are flat, and a table-scoped key would not be the setting.
// If a key is missing and the file contains any table section, the
// edit is refused: appending at the end would land inside the table
// and silently have no effect.
//
// This is the server-side edit: the server config has no singular
// compression-type keys (it negotiates through SUPPORTED_* lists),
// so only the ZSTD_* keys are written here. The node-side edit is
// editNodeCompressionLines.
func editCompressionLines(data []byte, settings CompressionSettings) ([]byte, error) {
	return editKeyValueLines(data, settings.values(), zstdKeyOrder)
}

// editNodeCompressionLines is the node-side edit: the three ZSTD_*
// keys plus the two negotiated compression-type keys derived from
// DictEnabled (see CompressionSettings.typeValues). The same
// line-based discipline and table refusal apply to all five keys.
func editNodeCompressionLines(data []byte, settings CompressionSettings) ([]byte, error) {
	values := settings.values()
	for k, v := range settings.typeValues() {
		values[k] = v
	}
	order := append(append([]string{}, zstdKeyOrder...), typeKeyOrder...)
	return editKeyValueLines(data, values, order)
}

// editKeyValueLines returns data with the lines assigning the keys
// in values replaced (or appended in appendOrder when absent). All
// other lines are returned byte-identical, including comments, blank
// lines and line endings. Lines inside a TOML table section are left
// alone; if a key is missing and the file contains any table section,
// the edit is refused: appending at the end would land inside the
// table and silently have no effect.
func editKeyValueLines(data []byte, values map[string]string, appendOrder []string) ([]byte, error) {
	found := map[string]bool{}
	inTable := false
	chunks := strings.SplitAfter(string(data), "\n")
	for i, chunk := range chunks {
		line := strings.TrimSuffix(chunk, "\n")
		line = strings.TrimSuffix(line, "\r")
		ending := chunk[len(line):]
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inTable = true
			continue
		}
		if inTable || strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		key = strings.Trim(key, `"'`)
		var target string
		for k := range values {
			if strings.EqualFold(key, k) {
				target = k
				break
			}
		}
		if target == "" {
			continue
		}
		rest := line[eq+1:]
		comment := ""
		if idx := tomlCommentIndex(rest); idx >= 0 {
			comment = rest[idx:]
			rest = rest[:idx]
		}
		_ = rest
		rebuilt := line[:eq+1] + " " + values[target]
		if comment != "" {
			rebuilt += " " + comment
		}
		chunks[i] = rebuilt + ending
		found[target] = true
	}
	var out strings.Builder
	out.WriteString(strings.Join(chunks, ""))
	if len(values) > 0 {
		// Append any missing key, in a fixed order.
		for _, key := range appendOrder {
			if found[key] {
				continue
			}
			if inTable {
				return nil, fmt.Errorf("config contains TOML table sections and %s is absent: refusing the line-based edit", key)
			}
			current := out.String()
			if current != "" && !strings.HasSuffix(current, "\n") {
				out.WriteString("\n")
			}
			out.WriteString(key + " = " + values[key] + "\n")
		}
	}
	return []byte(out.String()), nil
}

// tomlCommentIndex returns the index of a '#' that starts a TOML
// comment in s (outside any quoted string), or -1.
func tomlCommentIndex(s string) int {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && (inSingle || inDouble) && i+1 < len(s):
			i++
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == '#' && !inSingle && !inDouble:
			return i
		}
	}
	return -1
}

// validateEditedConfig reloads edited content with the real config
// loader via a temporary file in the same directory, so relative
// resolution behaves as it will for the installed file.
func validateEditedConfig(origPath string, edited []byte, load func(string) error) error {
	dir := filepath.Dir(origPath)
	tmp, err := os.CreateTemp(dir, ".zstd-validate-*.tmp")
	if err != nil {
		return fmt.Errorf("create validation copy: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(edited); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write validation copy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close validation copy: %w", err)
	}
	if err := load(tmpName); err != nil {
		return fmt.Errorf("edited config failed to reload: %w", err)
	}
	return nil
}

// installEditedConfig preserves orig as path+".bak" (atomic, 0600)
// and installs edited atomically (temp + rename, 0600). Callers must
// have validated edited already. Byte-identical content is a no-op.
func installEditedConfig(path string, orig, edited []byte) error {
	if bytes.Equal(orig, edited) {
		return nil
	}
	dir := filepath.Dir(path)
	bakTmp, err := os.CreateTemp(dir, ".zstd-bak-*.tmp")
	if err != nil {
		return fmt.Errorf("create backup copy: %w", err)
	}
	bakTmpName := bakTmp.Name()
	defer func() { _ = os.Remove(bakTmpName) }()
	if err := bakTmp.Chmod(0o600); err != nil {
		_ = bakTmp.Close()
		return fmt.Errorf("set backup copy mode: %w", err)
	}
	if _, err := bakTmp.Write(orig); err != nil {
		_ = bakTmp.Close()
		return fmt.Errorf("write backup copy: %w", err)
	}
	if err := bakTmp.Close(); err != nil {
		return fmt.Errorf("close backup copy: %w", err)
	}
	if err := os.Rename(bakTmpName, path+".bak"); err != nil {
		return fmt.Errorf("preserve previous config as %s.bak: %w", path, err)
	}
	if err := os.Chmod(path+".bak", 0o600); err != nil {
		return fmt.Errorf("set backup mode: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".zstd-edit-*.tmp")
	if err != nil {
		return fmt.Errorf("create edited config: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set edited config mode: %w", err)
	}
	if _, err := tmp.Write(edited); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write edited config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close edited config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install edited config %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("set edited config mode: %w", err)
	}
	return nil
}

type compressionFileTarget struct {
	path     string
	current  CompressionSettings
	load     func(string) error
	edit     func([]byte, CompressionSettings) ([]byte, error)
	isServer bool
}

// requireServerZSTDSupport refuses dictionary enablement when the
// server config's resolved SUPPORTED_* lists exclude zstd (type 1)
// in either direction: the server would resolve a negotiated zstd
// request to Off, and the dictionaries could not engage. The lists
// default to all types, so this only fires when an operator
// deliberately restricted them; the fix is to add 1 to both lists
// (or remove the restriction) by hand and retry. The check reads
// the current file, which the apply does not change for these lists,
// so it also describes the post-apply state.
func requireServerZSTDSupport(path string) error {
	cfg, err := config.LoadServerConfig(path)
	if err != nil {
		return err
	}
	allows := func(types []int) bool {
		for _, t := range types {
			if t == compression.TypeZSTD {
				return true
			}
		}
		return false
	}
	if !allows(cfg.SupportedUploadCompressionTypes) || !allows(cfg.SupportedDownloadCompressionTypes) {
		return fmt.Errorf("server config SUPPORTED_UPLOAD_COMPRESSION_TYPES/SUPPORTED_DOWNLOAD_COMPRESSION_TYPES exclude ZSTD (1): dictionary compression cannot engage; add 1 to both lists or remove the restriction, then retry")
	}
	return nil
}

// defaultNodeConfigContent is the minimal node config the panel creates
// when the node config file is absent. It holds only the five keys the
// panel manages (the three ZSTD_* keys plus the two negotiated
// compression-type keys) at their defaults (LZ4, dictionaries off) —
// the same defaults defaultClientConfig() uses. This file is the panel's
// shadow copy on the mother; the node itself runs from its own config
// on the node host. The installer should ship a full node config
// eventually; until then the panel must not fail closed on a missing
// file — it creates this one and proceeds.
const defaultNodeConfigContent = `# Created by the Nexounel panel: the node config file was absent, so the
# panel created it with the compression defaults (LZ4, dictionaries off).
# The panel manages only the ZSTD_* and compression-type keys in this file.
ZSTD_DICT_ENABLED = false
ZSTD_LEVEL = 0
ZSTD_LONG_ENABLED = false
UPLOAD_COMPRESSION_TYPE = 2
DOWNLOAD_COMPRESSION_TYPE = 2
`

// ensureNodeConfigFile creates the node config file with the compression
// defaults when it is absent, so a panel apply does not fail closed on
// a missing file. An existing file is left untouched. Any other error
// (e.g. a permission error) is returned so the panel can show it.
func ensureNodeConfigFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat node config %s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(defaultNodeConfigContent), 0o600); err != nil {
		return fmt.Errorf("create node config %s: %w", path, err)
	}
	return nil
}

// ApplyCompressionSettingsUpdate applies update to BOTH the server
// config file and the node config file. Both files are read, edited
// in memory and reload-validated BEFORE either is installed, so a
// bad edit on either side leaves both working configs untouched.
// Fields the update omits keep each file's own current value. The
// node edit additionally derives both negotiated compression-type
// keys from the resolved DictEnabled value (1/ZSTD on enable, 2/LZ4
// on disable); the server edit writes the ZSTD_* keys only, and
// enabling dictionaries is refused when the server's resolved
// SUPPORTED_* lists exclude zstd.
func ApplyCompressionSettingsUpdate(serverPath, nodePath string, update CompressionSettingsUpdate) error {
	// The node config file may not exist on the mother (the installer
	// does not ship it yet). Create it with the compression defaults
	// instead of failing closed; a real error (e.g. permission) is
	// still returned and shown in the panel.
	if err := ensureNodeConfigFile(nodePath); err != nil {
		return fmt.Errorf("node config: %w", err)
	}
	serverCurrent, err := loadServerCompressionSettings(serverPath)
	if err != nil {
		return fmt.Errorf("server config: %w", err)
	}
	nodeCurrent, err := loadNodeCompressionSettings(nodePath)
	if err != nil {
		return fmt.Errorf("node config: %w", err)
	}
	targets := []compressionFileTarget{
		{path: serverPath, current: serverCurrent, load: func(p string) error {
			_, err := config.LoadServerConfig(p)
			return err
		}, edit: editCompressionLines, isServer: true},
		{path: nodePath, current: nodeCurrent, load: func(p string) error {
			// Lenient: the node file on the mother is the panel's
			// shadow copy, not a runnable node config — validate
			// that it parses and the compression keys are valid,
			// not that it could run a node (see
			// loadNodeCompressionFile).
			_, err := loadNodeCompressionFile(p)
			return err
		}, edit: editNodeCompressionLines},
	}
	type prepared struct {
		target compressionFileTarget
		orig   []byte
		edited []byte
	}
	var ready []prepared
	for _, target := range targets {
		resolved, err := update.resolve(target.current)
		if err != nil {
			return err
		}
		if target.isServer && resolved.DictEnabled {
			if err := requireServerZSTDSupport(target.path); err != nil {
				return fmt.Errorf("server config: %w", err)
			}
		}
		orig, err := os.ReadFile(target.path)
		if err != nil {
			return fmt.Errorf("read config %s: %w", target.path, err)
		}
		edited, err := target.edit(orig, resolved)
		if err != nil {
			return err
		}
		if err := validateEditedConfig(target.path, edited, target.load); err != nil {
			return fmt.Errorf("config %s: %w", target.path, err)
		}
		ready = append(ready, prepared{target: target, orig: orig, edited: edited})
	}
	for i, p := range ready {
		if err := installEditedConfig(p.target.path, p.orig, p.edited); err != nil {
			if i == 0 {
				return err
			}
			return fmt.Errorf("server config updated but node config failed: %w", err)
		}
	}
	return nil
}

func loadServerCompressionSettings(path string) (CompressionSettings, error) {
	cfg, err := config.LoadServerConfig(path)
	if err != nil {
		return CompressionSettings{}, err
	}
	return CompressionSettings{DictEnabled: cfg.ZSTDDictEnabled, Level: cfg.ZSTDLevel, LongEnabled: cfg.ZSTDLongEnabled}, nil
}

// nodeCompressionKeys is the lenient view of a node config: only the
// five keys the panel manages. The node config file on the mother is
// the panel's shadow copy — it is not a complete runnable node config
// (a runnable node config needs an encryption key, domains, and a
// resolvers file, which live on the node host), so a full
// LoadClientConfig is the wrong validator here: it rejects a shadow
// file for missing keys the panel never manages. Decoding just these
// five keys lets the panel work with the shadow file, and a missing
// file reads as the compression defaults.
type nodeCompressionKeys struct {
	ZSTDDictEnabled       bool `toml:"ZSTD_DICT_ENABLED"`
	ZSTDLevel             int  `toml:"ZSTD_LEVEL"`
	ZSTDLongEnabled       bool `toml:"ZSTD_LONG_ENABLED"`
	UploadCompressionType int  `toml:"UPLOAD_COMPRESSION_TYPE"`
	DownloadCompressionType int `toml:"DOWNLOAD_COMPRESSION_TYPE"`
}

// loadNodeCompressionFile reads the five panel-managed keys from a node
// config file. A missing file reads as the compression defaults
// (LZ4, dictionaries off) — the caller creates the file with
// ensureNodeConfigFile before editing. A malformed file, or a
// compression value out of range, is a real error.
func loadNodeCompressionFile(path string) (CompressionSettings, error) {
	var keys nodeCompressionKeys
	// Defaults for keys the file omits: the documented LZ4 types.
	keys.UploadCompressionType = compression.TypeLZ4
	keys.DownloadCompressionType = compression.TypeLZ4
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return CompressionSettings{}, nil
		}
		return CompressionSettings{}, fmt.Errorf("stat node config %s: %w", path, err)
	}
	if _, err := toml.DecodeFile(path, &keys); err != nil {
		return CompressionSettings{}, fmt.Errorf("parse node config %s: %w", path, err)
	}
	settings := CompressionSettings{DictEnabled: keys.ZSTDDictEnabled, Level: keys.ZSTDLevel, LongEnabled: keys.ZSTDLongEnabled}
	if err := settings.validate(); err != nil {
		return CompressionSettings{}, err
	}
	// The compression-type keys are NOT validated here: the apply
	// overwrites them with the derived values (1/ZSTD on enable,
	// 2/LZ4 on disable), so a hand-set custom type in the file is
	// replaced, not rejected. (A test pins this: a file with
	// DOWNLOAD_COMPRESSION_TYPE = 3 must still apply, and the
	// apply restores it to 2.)
	return settings, nil
}

// loadNodeCompressionSettings reads the current compression settings
// from the node config file, leniently (see loadNodeCompressionFile).
func loadNodeCompressionSettings(path string) (CompressionSettings, error) {
	return loadNodeCompressionFile(path)
}
