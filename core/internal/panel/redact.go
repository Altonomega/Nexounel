package panel

import (
	"regexp"
	"strings"
)

// secretLinePattern matches log lines that may carry secret material.
// Any matching line is dropped entirely, never rendered.
var secretLinePattern = regexp.MustCompile(`(?i)\b(key|password|secret|token|authorization|passwd)\b`)

// ShouldDropLogLine reports whether a log line must never be rendered.
func ShouldDropLogLine(line string) bool {
	return secretLinePattern.MatchString(line)
}

// RedactLogLines drops every line that may carry secret material.
func RedactLogLines(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if ShouldDropLogLine(line) {
			continue
		}
		out = append(out, line)
	}
	return out
}

// ScrubSecrets replaces every occurrence of each supplied secret value in
// text with "[redacted]". Values shorter than 4 characters are ignored so
// short fragments cannot blank out ordinary text. Use it for job logs and
// command output that might echo a value the admin typed.
func ScrubSecrets(text string, secrets []string) string {
	for _, secret := range secrets {
		if len(secret) < 4 {
			continue
		}
		if strings.Contains(text, secret) {
			text = strings.ReplaceAll(text, secret, "[redacted]")
		}
	}
	return text
}
