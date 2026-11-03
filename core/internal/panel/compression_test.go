package panel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
)

const fixtureServerConfig = `# Server fixture: comments and unrelated keys must survive.
UDP_PORT = 53
DOMAIN = ["tunnel.example.invalid"]
ZSTD_DICT_ENABLED = false # keep this comment
ZSTD_LEVEL = 0
ZSTD_LONG_ENABLED = false
# Trailing comment.
`

const fixtureNodeConfig = `# Node fixture.
DOMAINS = ["tunnel.example.invalid"]
ENCRYPTION_KEY = "` + "00112233445566778899aabbccddeeff" + `"
ZSTD_DICT_ENABLED = false
ZSTD_LEVEL = 3
# ZSTD_LONG_ENABLED is intentionally absent: the append path is exercised.
LISTEN_PORT = 18000
`

func writeCompressionFixtures(t *testing.T) (dir, serverPath, nodePath string) {
	t.Helper()
	dir = t.TempDir()
	serverPath = filepath.Join(dir, "nexounel-server.toml")
	nodePath = filepath.Join(dir, "nexounel-node.toml")
	if err := os.WriteFile(serverPath, []byte(fixtureServerConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nodePath, []byte(fixtureNodeConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte("8.8.8.8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Fixtures must load before any edit: the tests prove edits, not
	// fixture validity.
	if _, err := config.LoadServerConfig(serverPath); err != nil {
		t.Fatalf("server fixture does not load: %v", err)
	}
	if _, err := config.LoadClientConfig(nodePath); err != nil {
		t.Fatalf("node fixture does not load: %v", err)
	}
	return dir, serverPath, nodePath
}

func boolPtr(b bool) *bool { return &b }
func intPtr(i int) *int    { return &i }

// assertOnlyZSTDChanged checks that every non-ZSTD line of before
// survives byte-identical and in order inside after, and that after
// contains no unexpected new lines beyond ZSTD assignments.
func assertOnlyZSTDChanged(t *testing.T, before, after []byte) {
	t.Helper()
	isZSTD := func(line string) bool {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			return false
		}
		eq := strings.Index(trimmed, "=")
		if eq < 0 {
			return false
		}
		key := strings.TrimSpace(trimmed[:eq])
		return key == "ZSTD_DICT_ENABLED" || key == "ZSTD_LEVEL" || key == "ZSTD_LONG_ENABLED"
	}
	beforeLines := strings.Split(strings.TrimSuffix(string(before), "\n"), "\n")
	afterLines := strings.Split(strings.TrimSuffix(string(after), "\n"), "\n")
	j := 0
	for _, line := range beforeLines {
		if isZSTD(line) {
			continue
		}
		found := false
		for ; j < len(afterLines); j++ {
			if afterLines[j] == line {
				found = true
				j++
				break
			}
			if !isZSTD(afterLines[j]) {
				t.Fatalf("non-ZSTD line %q was changed or dropped; after:\n%s", line, string(after))
			}
		}
		if !found {
			t.Fatalf("non-ZSTD line %q missing from edited file:\n%s", line, string(after))
		}
	}
	for ; j < len(afterLines); j++ {
		if !isZSTD(afterLines[j]) {
			t.Fatalf("unexpected new non-ZSTD line %q in edited file:\n%s", afterLines[j], string(after))
		}
	}
}

func TestEditCompressionLinesReplacesAndAppends(t *testing.T) {
	settings := CompressionSettings{DictEnabled: true, Level: 9, LongEnabled: false}
	edited, err := editCompressionLines([]byte(fixtureServerConfig), settings)
	if err != nil {
		t.Fatal(err)
	}
	assertOnlyZSTDChanged(t, []byte(fixtureServerConfig), edited)
	if !strings.Contains(string(edited), "ZSTD_DICT_ENABLED = true # keep this comment") {
		t.Fatalf("trailing comment not preserved:\n%s", edited)
	}
	if !strings.Contains(string(edited), "ZSTD_LEVEL = 9") {
		t.Fatalf("level not replaced:\n%s", edited)
	}

	// Node fixture: the absent long key is appended; the rest is untouched.
	editedNode, err := editCompressionLines([]byte(fixtureNodeConfig), settings)
	if err != nil {
		t.Fatal(err)
	}
	assertOnlyZSTDChanged(t, []byte(fixtureNodeConfig), editedNode)
	if !strings.Contains(string(editedNode), "ZSTD_LONG_ENABLED = false\n") {
		t.Fatalf("missing key not appended:\n%s", editedNode)
	}
	if _, err := config.LoadClientConfig(writeTempConfig(t, editedNode)); err != nil {
		t.Fatalf("edited node config does not reload: %v", err)
	}
}

func writeTempConfig(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "check.toml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// The client loader resolves the resolvers file relative to the
	// config directory; point it at a fixture copy.
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "client_resolvers.txt"), []byte("8.8.8.8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEditCompressionLinesIgnoresCommentsAndTables(t *testing.T) {
	settings := CompressionSettings{DictEnabled: true, Level: 5, LongEnabled: true}
	// A commented-out key must not count as present: the real key is appended.
	data := "# ZSTD_LEVEL = 99\nZSTD_DICT_ENABLED = false\nZSTD_LONG_ENABLED = false\n"
	edited, err := editCompressionLines([]byte(data), settings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(edited), "# ZSTD_LEVEL = 99") {
		t.Fatalf("commented line changed:\n%s", edited)
	}
	if !strings.Contains(string(edited), "ZSTD_LEVEL = 5") {
		t.Fatalf("appended key missing:\n%s", edited)
	}
	// A key inside a table section is not the setting; appending is refused.
	tableData := "ZSTD_DICT_ENABLED = false\nZSTD_LEVEL = 1\n[other]\nfoo = 1\n"
	if _, err := editCompressionLines([]byte(tableData), settings); err == nil {
		t.Fatal("table-section append must be refused")
	}
	// All keys present before the table: the edit succeeds.
	tableDataFull := "ZSTD_DICT_ENABLED = false\nZSTD_LEVEL = 1\nZSTD_LONG_ENABLED = false\n[other]\nfoo = 1\n"
	if _, err := editCompressionLines([]byte(tableDataFull), settings); err != nil {
		t.Fatalf("top-level edit with a later table must succeed: %v", err)
	}
}

func TestApplyCompressionSettingsRoundTrip(t *testing.T) {
	_, serverPath, nodePath := writeCompressionFixtures(t)
	serverBefore, _ := os.ReadFile(serverPath)
	nodeBefore, _ := os.ReadFile(nodePath)

	update := CompressionSettingsUpdate{DictEnabled: boolPtr(true), Level: intPtr(9), LongEnabled: boolPtr(false)}
	if err := ApplyCompressionSettingsUpdate(serverPath, nodePath, update); err != nil {
		t.Fatal(err)
	}
	serverAfter, _ := os.ReadFile(serverPath)
	nodeAfter, _ := os.ReadFile(nodePath)
	assertOnlyZSTDChanged(t, serverBefore, serverAfter)
	assertOnlyZSTDChanged(t, nodeBefore, nodeAfter)

	// Reloaded values match the request on both sides.
	sc, err := config.LoadServerConfig(serverPath)
	if err != nil {
		t.Fatal(err)
	}
	if !sc.ZSTDDictEnabled || sc.ZSTDLevel != 9 || sc.ZSTDLongEnabled {
		t.Fatalf("server settings after apply: %+v", sc)
	}
	nc, err := config.LoadClientConfig(nodePath)
	if err != nil {
		t.Fatal(err)
	}
	if !nc.ZSTDDictEnabled || nc.ZSTDLevel != 9 || nc.ZSTDLongEnabled {
		t.Fatalf("node settings after apply: %+v", nc)
	}
	// Previous files preserved as .bak, byte-identical.
	serverBak, err := os.ReadFile(serverPath + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if string(serverBak) != string(serverBefore) {
		t.Fatal("server .bak does not hold the previous file")
	}
	nodeBak, err := os.ReadFile(nodePath + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if string(nodeBak) != string(nodeBefore) {
		t.Fatal("node .bak does not hold the previous file")
	}
	// Idempotent re-apply: no rewrite, no .bak churn, no temp litter.
	if err := ApplyCompressionSettingsUpdate(serverPath, nodePath, update); err != nil {
		t.Fatal(err)
	}
	// Re-applying identical values still rewrites the value tokens only
	// if formatting differs; here formatting is already canonical, so
	// the files must be unchanged and the .bak must still hold the
	// pre-first-apply content.
	serverAgain, _ := os.ReadFile(serverPath)
	if string(serverAgain) != string(serverAfter) {
		t.Fatal("idempotent apply changed the server file")
	}
	serverBakAgain, _ := os.ReadFile(serverPath + ".bak")
	if string(serverBakAgain) != string(serverBefore) {
		t.Fatal("idempotent apply rewrote the .bak")
	}
	entries, err := os.ReadDir(filepath.Dir(serverPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") || strings.HasPrefix(e.Name(), ".zstd-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestApplyCompressionSettingsPartialUpdate(t *testing.T) {
	_, serverPath, nodePath := writeCompressionFixtures(t)
	// Only the level changes; dict/long keep each file's own values
	// (node starts at level 3, server at 0).
	if err := ApplyCompressionSettingsUpdate(serverPath, nodePath, CompressionSettingsUpdate{Level: intPtr(9)}); err != nil {
		t.Fatal(err)
	}
	sc, _ := config.LoadServerConfig(serverPath)
	nc, _ := config.LoadClientConfig(nodePath)
	if sc.ZSTDLevel != 9 || nc.ZSTDLevel != 9 {
		t.Fatalf("levels: server %d node %d", sc.ZSTDLevel, nc.ZSTDLevel)
	}
	if sc.ZSTDDictEnabled || nc.ZSTDDictEnabled {
		t.Fatal("partial update changed dict enablement")
	}
}

func TestApplyCompressionSettingsBadEditNeverReplaces(t *testing.T) {
	_, serverPath, nodePath := writeCompressionFixtures(t)
	serverBefore, _ := os.ReadFile(serverPath)
	nodeBefore, _ := os.ReadFile(nodePath)

	// Invalid level: rejected before any file is touched.
	err := ApplyCompressionSettingsUpdate(serverPath, nodePath, CompressionSettingsUpdate{Level: intPtr(23)})
	if err == nil {
		t.Fatal("level 23 must be rejected")
	}
	// Missing file: rejected, other file untouched.
	missing := filepath.Join(t.TempDir(), "missing.toml")
	if err := ApplyCompressionSettingsUpdate(missing, nodePath, CompressionSettingsUpdate{Level: intPtr(9)}); err == nil {
		t.Fatal("missing server config must be rejected")
	}
	// Duplicate key in the server file: the edited content cannot
	// reload, so nothing is installed.
	dup := "UDP_PORT = 53\nDOMAIN = [\"tunnel.example.invalid\"]\nZSTD_LEVEL = 1\nZSTD_LEVEL = 2\nZSTD_DICT_ENABLED = false\nZSTD_LONG_ENABLED = false\n"
	if err := os.WriteFile(serverPath, []byte(dup), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyCompressionSettingsUpdate(serverPath, nodePath, CompressionSettingsUpdate{Level: intPtr(9)}); err == nil {
		t.Fatal("duplicate-key config must be rejected")
	}
	if got, _ := os.ReadFile(serverPath); string(got) != dup {
		t.Fatalf("duplicate-key file was modified:\n%s", got)
	}
	if got, _ := os.ReadFile(nodePath); string(got) != string(nodeBefore) {
		t.Fatal("node file changed after a rejected server edit")
	}
	if _, err := os.Stat(serverPath + ".bak"); !os.IsNotExist(err) {
		t.Fatal("a .bak was written for a rejected edit")
	}
	_ = serverBefore
}
