package panel

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestFixturesUseOnlyFakeValues scans this package's Go sources and
// asserts fixtures use obviously-fake values: no real operator domain,
// and every literal IP is either loopback, a public resolver, or a
// documentation-range address.
func TestFixturesUseOnlyFakeValues(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	forbiddenDomain := "mash" + "ani.tr" // constructed so this file itself does not contain the literal
	ipPattern := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(".", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		content := string(data)
		if strings.Contains(strings.ToLower(content), forbiddenDomain) {
			t.Fatalf("%s contains a real operator domain", entry.Name())
		}
		for _, ipStr := range ipPattern.FindAllString(content, -1) {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				t.Fatalf("%s contains malformed IP %q", entry.Name(), ipStr)
			}
			if ip.IsLoopback() {
				continue
			}
			switch ipStr {
			case "0.0.0.0", "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220":
				continue
			}
			// Documentation ranges only.
			_, doc1, _ := net.ParseCIDR("203.0.113.0/24")
			_, doc2, _ := net.ParseCIDR("192.0.2.0/24")
			_, doc3, _ := net.ParseCIDR("198.51.100.0/24")
			if doc1.Contains(ip) || doc2.Contains(ip) || doc3.Contains(ip) {
				continue
			}
			t.Fatalf("%s contains non-fixture IP %q", entry.Name(), ipStr)
		}
		// Fixture domains must be example.invalid (or the standard
		// example names); any other ".invalid" use is fine, but a
		// ".com"/".net" literal in a fixture is suspicious.
		for _, m := range regexp.MustCompile(`[A-Za-z0-9-]+\.(com|net|org|io)\b`).FindAllString(content, -1) {
			if m == "example.com" {
				continue
			}
			// Allow references to the Cloudflare API host, the Go
			// module path, and import paths, which are not fixture domains.
			if strings.Contains(m, "cloudflare.com") || strings.Contains(m, "github.com") || m == "golang.org" {
				continue
			}
			t.Fatalf("%s contains suspicious domain literal %q", entry.Name(), m)
		}
	}
	// Spot-check the shared fixture values themselves.
	if !strings.Contains(DefaultResolversContent(), "8.8.8.8") {
		t.Fatal("default resolvers fixture changed unexpectedly")
	}
}
