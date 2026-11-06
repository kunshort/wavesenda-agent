package redact

import "strings"

import "testing"

func TestCredentialsNeverLeaveTheMachine(t *testing.T) {
	secrets := []string{
		"DATABASE_URL=postgres://admin:hunter2@db.internal/app",
		"api_key=ws_live_abcdefghijkl",
		"AKIAIOSFODNN7EXAMPLE",
		"PASSWORD: s3cr3tvalue",
		"token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27u",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
	}
	for _, secret := range secrets {
		cleaned := Clean("before\n" + secret + "\nafter")
		for _, giveaway := range []string{"hunter2", "ws_live_abcdefghijkl", "AKIAIOSFODNN7EXAMPLE", "s3cr3tvalue", "MIIEpAIBAAKCAQEA"} {
			if strings.Contains(cleaned, giveaway) {
				t.Errorf("%q survived redaction: %s", giveaway, cleaned)
			}
		}
		if !strings.Contains(cleaned, "before") || !strings.Contains(cleaned, "after") {
			t.Errorf("redaction ate the surrounding log: %s", cleaned)
		}
	}
}

func TestOrdinaryLogsAreLeftAlone(t *testing.T) {
	log := "nginx: worker process started\nGET /checkout 200 18ms"
	if Clean(log) != log {
		t.Errorf("an ordinary log was altered: %s", Clean(log))
	}
}

func TestTruncateSaysItTruncated(t *testing.T) {
	long := strings.Repeat("x", 100)
	out := Truncate(long, 20)
	if len(out) > 60 || !strings.Contains(out, "truncated") {
		t.Errorf("unexpected truncation: %q", out)
	}
	if Truncate("short", 20) != "short" {
		t.Error("truncated something that fitted")
	}
}

func TestTheAgentsOwnTokenIsScrubbed(t *testing.T) {
	// `generate_token` joins the prefix and the secret with no separator, so a
	// pattern expecting `wss_` matched nothing — and the one credential this
	// program holds would have travelled in a log tail.
	log := "config: {\"token\": \"wss8ZkqpMuAbcdefghijklmnopqrstuv\"}"
	if strings.Contains(Clean(log), "8ZkqpMuAbcdefghijklmnopqrstuv") {
		t.Errorf("the agent token survived redaction: %s", Clean(log))
	}
}
