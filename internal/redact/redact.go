// Package redact removes anything that looks like a credential before it
// leaves the machine.
//
// This runs here, on the customer's server, rather than only on the far side.
// Log output is the likeliest place for a secret to appear by accident, and a
// secret that never crosses the network cannot be read out of a chat thread,
// a model's context window or a database backup.
package redact

import "regexp"

var patterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:password|passwd|secret|token|api[_-]?key|bearer)\b\s*[:=]\s*\S+`),
	regexp.MustCompile(`(?i)\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)\b[a-z0-9._%+-]+:[^\s@/]{6,}@[a-z0-9.-]+\b`),
	regexp.MustCompile(`\bws_live_[A-Za-z0-9_-]{8,}\b`),
	// This agent's own token. `generate_token` joins prefix and secret with
	// no separator, so a pattern expecting `wss_` matched nothing at all.
	regexp.MustCompile(`\bwss[A-Za-z0-9_-]{20,}\b`),
	regexp.MustCompile(`(?i)\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
}

// Clean replaces every credential-shaped run with a marker.
func Clean(text string) string {
	for _, pattern := range patterns {
		text = pattern.ReplaceAllString(text, "[redacted]")
	}
	return text
}

// Truncate caps output at a size worth sending. The far side truncates too;
// this one saves the bandwidth and the tokens.
func Truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "\n… (truncated)"
}
