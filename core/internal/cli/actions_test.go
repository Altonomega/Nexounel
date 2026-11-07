package cli

import (
	"strings"
	"testing"
	"time"
)

const sampleTrafficLine = `Nov 07 09:51:28 main nexounel-node[4724]: 2026/11/07 09:51:28 [CottenDns Client] [INFO] 📊 ↑ 10.91 KB/s (Total: 480.35 MB) | ↓ 13.51 KB/s (Total: 692.83 MB) | loss 0.0% | resolvers 774 | transport UDP/53 | queues 0/0/0 | drops rx=0 tx=0 | recoveries 0 | stream-fail dial=0 write=0 | offered 46 q/s | governor cap=2000 throttled=1047908`

func TestParseTrafficLine(t *testing.T) {
	s := parseTrafficLine(sampleTrafficLine)
	if s.Loss != 0.0 || s.Resolvers != 774 {
		t.Errorf("loss/resolvers = %.1f/%d, want 0.0/774", s.Loss, s.Resolvers)
	}
	if s.Queue0 != 0 || s.Queue1 != 0 || s.Queue2 != 0 {
		t.Errorf("queues = %d/%d/%d, want 0/0/0", s.Queue0, s.Queue1, s.Queue2)
	}
	if s.Offered != 46 || s.GovernorCap != 2000 {
		t.Errorf("offered/cap = %.0f/%.0f, want 46/2000", s.Offered, s.GovernorCap)
	}
}

func TestParseTrafficLineLossy(t *testing.T) {
	line := strings.Replace(sampleTrafficLine, "loss 0.0%", "loss 12.2%", 1)
	line = strings.Replace(line, "resolvers 774", "resolvers 806", 1)
	line = strings.Replace(line, "queues 0/0/0", "queues 1/2/92", 1)
	s := parseTrafficLine(line)
	if s.Loss != 12.2 || s.Resolvers != 806 {
		t.Errorf("loss/resolvers = %.1f/%d, want 12.2/806", s.Loss, s.Resolvers)
	}
	if s.Queue0 != 1 || s.Queue1 != 2 || s.Queue2 != 92 {
		t.Errorf("queues = %d/%d/%d, want 1/2/92", s.Queue0, s.Queue1, s.Queue2)
	}
}

func TestParseTrafficLineGarbage(t *testing.T) {
	s := parseTrafficLine("nothing to see here")
	if s.Loss != 0 || s.Resolvers != 0 {
		t.Errorf("garbage line parsed as %+v", s)
	}
}

func TestLastTrafficLine(t *testing.T) {
	log := "Nov 07 09:00:00 boot\n" + sampleTrafficLine + "\nNov 07 09:01:00 something else\n"
	got := lastTrafficLine(log)
	if !strings.Contains(got, "loss 0.0%") {
		t.Errorf("lastTrafficLine = %q", got)
	}
	if got := lastTrafficLine("no traffic here\n"); got != "" {
		t.Errorf("lastTrafficLine with no sample = %q", got)
	}
}

func TestParseMetricValue(t *testing.T) {
	body := `# HELP cottendns_active_sessions gauge
# TYPE cottendns_active_sessions gauge
cottendns_active_sessions 3
# TYPE cottendns_active_streams gauge
cottendns_active_streams 7
`
	if v, ok := parseMetricValue(body, "cottendns_active_sessions"); !ok || v != 3 {
		t.Errorf("sessions = %d, %v, want 3, true", v, ok)
	}
	if v, ok := parseMetricValue(body, "cottendns_active_streams"); !ok || v != 7 {
		t.Errorf("streams = %d, %v, want 7, true", v, ok)
	}
	if _, ok := parseMetricValue(body, "cottendns_missing"); ok {
		t.Errorf("missing metric reported found")
	}
}

func TestFormatDuration(t *testing.T) {
	cases := []struct {
		seconds int64
		want    string
	}{
		{45, "45s"},
		{90, "1m30s"},
		{3661, "1h1m"},
		{7320, "2h2m"},
	}
	for _, c := range cases {
		if got := formatDuration(time.Duration(c.seconds) * time.Second); got != c.want {
			t.Errorf("formatDuration(%ds) = %q, want %q", c.seconds, got, c.want)
		}
	}
}
