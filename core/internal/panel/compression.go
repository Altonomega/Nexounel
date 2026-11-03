package panel

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
)

// Compression settings editing.
//
// The settings live as three TOML keys (ZSTD_DICT_ENABLED, ZSTD_LEVEL,
// ZSTD_LONG_ENABLED) in two config files the panel does not own: the
// server config and the node config. A map round-trip through the
// config loaders would drop comments, ordering and unknown fields, so
// the edit here is deliberately line-based: only lines assigning one
// of the three keys are touched (their value token is replaced,
// trailing comments preserved); every other byte of the file is
// preserved verbatim. Missing keys are appended. The edited content
// is validated by reloading it with the real config loader before
// anything is installed, and the previous file is preserved as a
// .bak next to it. A failed edit never replaces a working config.

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
func editCompressionLines(data []byte, settings CompressionSettings) ([]byte, error) {
	values := settings.values()
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
		for _, key := range []string{"ZSTD_DICT_ENABLED", "ZSTD_LEVEL", "ZSTD_LONG_ENABLED"} {
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
	path    string
	current CompressionSettings
	load    func(string) error
}

// ApplyCompressionSettingsUpdate applies update to BOTH the server
// config file and the node config file. Both files are read, edited
// in memory and reload-validated BEFORE either is installed, so a
// bad edit on either side leaves both working configs untouched.
// Fields the update omits keep each file's own current value.
func ApplyCompressionSettingsUpdate(serverPath, nodePath string, update CompressionSettingsUpdate) error {
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
		}},
		{path: nodePath, current: nodeCurrent, load: func(p string) error {
			_, err := config.LoadClientConfig(p)
			return err
		}},
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
		orig, err := os.ReadFile(target.path)
		if err != nil {
			return fmt.Errorf("read config %s: %w", target.path, err)
		}
		edited, err := editCompressionLines(orig, resolved)
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

func loadNodeCompressionSettings(path string) (CompressionSettings, error) {
	cfg, err := config.LoadClientConfig(path)
	if err != nil {
		return CompressionSettings{}, err
	}
	return CompressionSettings{DictEnabled: cfg.ZSTDDictEnabled, Level: cfg.ZSTDLevel, LongEnabled: cfg.ZSTDLongEnabled}, nil
}
