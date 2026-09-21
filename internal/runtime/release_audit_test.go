package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Execute the actual gateway policy script with controlled DNS and transport.
// No network is used and the containment transition has no timing dependency.
func TestGatewayContainmentDuringResolution(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"allowlist", "asklist"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("allowed.test\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	script := strings.ReplaceAll(gatewayHandler, "/run/ghost-observation", root)
	script = strings.ReplaceAll(script, "/run/ghost-policy", root)
	script = strings.Replace(script, "IFS= read -r request_line", `resolve_destination() { destination=93.184.216.34; : > "`+root+`/contained"; }
nc() { echo TRANSPORT_OPENED; }
IFS= read -r request_line`, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	cmd.Stdin = strings.NewReader("CONNECT allowed.test:443 HTTP/1.1\r\n\r\n")
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "403 Forbidden") || strings.Contains(string(output), "TRANSPORT_OPENED") {
		t.Fatalf("stale containment allowed connection: %s %v", output, err)
	}
	events, err := os.ReadFile(filepath.Join(root, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(events), `"decision":"ALLOW"`) || !strings.Contains(string(events), `"contained":true`) {
		t.Fatalf("incorrect evidence: %s", events)
	}
}

func TestGatewayEvidenceFailureDeniesConnection(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"allowlist", "asklist"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("allowed.test\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "events.jsonl"), 0700); err != nil {
		t.Fatal(err)
	}
	script := strings.ReplaceAll(strings.ReplaceAll(gatewayHandler, "/run/ghost-observation", root), "/run/ghost-policy", root)
	script = strings.Replace(script, "IFS= read -r request_line", "resolve_destination() { destination=93.184.216.34; }\nIFS= read -r request_line", 1)
	cmd := exec.Command("sh", "-c", script)
	cmd.Stdin = strings.NewReader("CONNECT allowed.test:443 HTTP/1.1\r\n\r\n")
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "403 Forbidden") || strings.Contains(string(output), "200 Connection") {
		t.Fatalf("unrecorded connection allowed: %s %v", output, err)
	}
}

func TestGatewayRejectsContradictoryApprovalResponses(t *testing.T) {
	for _, response := range []string{"ALLOW_ONCE AUTOMATIC_FAIL_CLOSED approval_unavailable", "ALLOW_SESSION AUTOMATIC_FAIL_CLOSED approval_unavailable", "ALLOW_ONCE SESSION_APPROVAL matching_session_approval", "DENY SESSION_APPROVAL matching_session_approval"} {
		t.Run(response, func(t *testing.T) {
			root := t.TempDir()
			for _, name := range []string{"approval-requests", "approval-responses"} {
				if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
					t.Fatal(err)
				}
			}
			script := strings.Split(gatewayHandler, "IFS= read -r request_line")[0]
			script = strings.ReplaceAll(script, "/run/ghost-observation", root)
			script += `mv() { command mv "$@"; printf '%s\n' '` + response + `' > "` + root + `/approval-responses/${2##*/}"; }
host=allowed.test; scheme=https; port=443; method=CONNECT
request_approval && exit 99
exit 0
`
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if output, err := exec.CommandContext(ctx, "sh", "-c", script).CombinedOutput(); err != nil {
				t.Fatalf("contradictory approval accepted: %s %v", output, err)
			}
			evidence, err := os.ReadFile(filepath.Join(root, "events.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(evidence), "APPROVAL_GRANTED") || !strings.Contains(string(evidence), "malformed_broker_response") {
				t.Fatalf("incorrect evidence: %s", evidence)
			}
		})
	}
}
