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

func TestRuntimeEvidenceCollectionIsBounded(t *testing.T) {
	for _, kind := range []string{"bytes", "records"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.jsonl")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "bytes" {
				err = f.Truncate(16*1024*1024 + 1)
			} else {
				_, err = f.WriteString(strings.Repeat("{}\n", 10001))
			}
			if err != nil {
				t.Fatal(err)
			}
			f.Close()
			if _, err := readSentinelEvents(path); err == nil {
				t.Fatal("unbounded evidence accepted")
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal("original evidence was removed")
			}
		})
	}
}

func TestNoncanonicalRootAndOverflowIdentityFailClosed(t *testing.T) {
	for _, id := range []string{"00", "0000000000", "4294967296"} {
		if _, err := validateGuestIdentity(id, "1000"); err == nil {
			t.Fatalf("unsafe UID %s accepted", id)
		}
		if _, err := validateGuestIdentity("1000", id); err == nil {
			t.Fatalf("unsafe GID %s accepted", id)
		}
	}
}

func TestOOMOutputBoundAppliesDuringCollection(t *testing.T) {
	var output oomOutput
	if _, err := output.Write(make([]byte, 64*1024)); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("x")); err == nil || output.Len() != 64*1024 {
		t.Fatal("OOM collection grew past its bound")
	}
}

func TestGatewayHTTPForwardsOnlyApprovedRequestBody(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"allowlist", "asklist"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("allowed.test\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	script := strings.ReplaceAll(strings.ReplaceAll(gatewayHandler, "/run/ghost-observation", root), "/run/ghost-policy", root)
	script = strings.ReplaceAll(script, "/tmp/ghost-proxy.", root+"/ghost-proxy.")
	script = strings.Replace(script, "IFS= read -r request_line", `resolve_destination() { destination=93.184.216.34; }
nc() { cat > "`+root+`/forwarded"; }
IFS= read -r request_line`, 1)
	cmd := exec.Command("sh", "-c", script)
	cmd.Stdin = strings.NewReader("POST http://allowed.test/first HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloPOST /second HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gateway: %s %v", output, err)
	}
	forwarded, err := os.ReadFile(filepath.Join(root, "forwarded"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(forwarded), "\r\n\r\nhello") || strings.Contains(string(forwarded), "/second") {
		t.Fatalf("incorrect HTTP body/framing: %q", forwarded)
	}
}

func TestGatewayRejectsAmbiguousHTTPFramingBeforeApproval(t *testing.T) {
	for _, headers := range []string{"Content-Length: 1\r\nContent-Length: 1\r\n", "Transfer-Encoding: chunked\r\n", "Content-Length: -1\r\n", "Expect: 100-continue\r\n", "Upgrade: websocket\r\n"} {
		t.Run(headers, func(t *testing.T) {
			root := t.TempDir()
			script := strings.ReplaceAll(gatewayHandler, "/run/ghost-observation", root)
			script = strings.Replace(script, "IFS= read -r request_line", `policy_gate() { echo POLICY_REACHED; return 2; }
IFS= read -r request_line`, 1)
			cmd := exec.Command("sh", "-c", script)
			cmd.Stdin = strings.NewReader("POST http://allowed.test/ HTTP/1.1\r\n" + headers + "\r\n")
			output, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(output), "403 Forbidden") || strings.Contains(string(output), "POLICY_REACHED") {
				t.Fatalf("ambiguous framing reached approval: %s %v", output, err)
			}
		})
	}
}
