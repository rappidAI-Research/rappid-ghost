package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/approval"
	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
)

func TestApprovalBrokerReturnsNarrowControllerResolution(t *testing.T) {
	policyValue, err := ghostnetwork.NewPolicyWithApproval("allowlist", nil, []string{"approval.test"})
	if err != nil {
		t.Fatal(err)
	}
	sessionDir := t.TempDir()
	request := RunRequest{
		SessionID: "session_test", SessionDir: sessionDir, NetworkPolicy: policyValue,
		ApprovalHandler: approvalHandlerFunc(func(context.Context, approval.Request) (approval.Response, error) {
			return approval.Response{Scope: approval.AllowOnce}, nil
		}),
		ApprovalTimeout: time.Second,
	}
	observation, err := prepareObservation(request)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := startApprovalBroker(context.Background(), request, observation)
	if err != nil {
		t.Fatal(err)
	}
	name := "approval.ABC123"
	payload := `{"id":"approval.ABC123","scheme":"https","host":"approval.test","port":443,"method":"CONNECT"}`
	publishApprovalFixture(t, observation, name, payload)
	responsePath := filepath.Join(observation.approvalResponses, name)
	deadline := time.Now().Add(time.Second)
	for {
		data, readErr := os.ReadFile(responsePath)
		if readErr == nil {
			if strings.TrimSpace(string(data)) != "ALLOW_ONCE USER_DECISION user_allowed_once" {
				t.Fatalf("broker response = %q", data)
			}
			break
		}
		if !os.IsNotExist(readErr) {
			t.Fatal(readErr)
		}
		if time.Now().After(deadline) {
			t.Fatal("approval broker did not publish a response")
		}
		time.Sleep(time.Millisecond)
	}
	if err := broker.stop(); err != nil {
		t.Fatal(err)
	}
}

func TestApprovalBrokerRejectsRequestsOutsideAskPolicy(t *testing.T) {
	policyValue, err := ghostnetwork.NewPolicyWithApproval("allowlist", nil, []string{"approval.test"})
	if err != nil {
		t.Fatal(err)
	}
	request := RunRequest{SessionID: "session_test", SessionDir: t.TempDir(), NetworkPolicy: policyValue}
	observation, err := prepareObservation(request)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := startApprovalBroker(context.Background(), request, observation)
	if err != nil {
		t.Fatal(err)
	}
	name := "approval.ABC123"
	payload := `{"id":"approval.ABC123","scheme":"https","host":"other.test","port":443,"method":"CONNECT"}`
	publishApprovalFixture(t, observation, name, payload)
	deadline := time.Now().Add(time.Second)
	for {
		broker.errMu.Lock()
		failed := broker.err != nil
		broker.errMu.Unlock()
		if failed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("approval broker did not reject an out-of-policy request")
		}
		time.Sleep(time.Millisecond)
	}
	<-broker.done
	validName := "approval.DEF456"
	validPayload := `{"id":"approval.DEF456","scheme":"https","host":"approval.test","port":443,"method":"CONNECT"}`
	publishApprovalFixture(t, observation, validName, validPayload)
	if _, err := os.Stat(filepath.Join(observation.approvalResponses, validName)); !os.IsNotExist(err) {
		t.Fatalf("failed broker continued issuing approvals: %v", err)
	}
	if err := broker.stop(); err == nil || !strings.Contains(err.Error(), "outside configured ASK policy") {
		t.Fatalf("broker error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(observation.approvalResponses, name)); !os.IsNotExist(err) {
		t.Fatalf("out-of-policy request received a response: %v", err)
	}
}

type approvalHandlerFunc func(context.Context, approval.Request) (approval.Response, error)

// Match the gateway protocol: write outside the watched request directory,
// then atomically rename on the same filesystem so the broker sees a complete
// request. WriteFile directly in that directory races the broker's first scan.
func publishApprovalFixture(t *testing.T, observation observationPaths, name, payload string) {
	t.Helper()
	temporary := filepath.Join(observation.dir, name+".pending")
	if err := os.WriteFile(temporary, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, filepath.Join(observation.approvalRequests, name)); err != nil {
		t.Fatal(err)
	}
}

func (f approvalHandlerFunc) Decide(ctx context.Context, request approval.Request) (approval.Response, error) {
	return f(ctx, request)
}

func TestApprovalProtocolMalformedArtifactsFailClosed(t *testing.T) {
	cases := map[string]string{
		"truncated":     `{"id":`,
		"unknown-field": `{"id":"approval.ABC123","scheme":"http","host":"approval.test","port":80,"method":"GET","grant":true}`,
		"trailing":      `{"id":"approval.ABC123","scheme":"http","host":"approval.test","port":80,"method":"GET"} {}`,
		"identity":      `{"id":"approval.OTHER","scheme":"http","host":"approval.test","port":80,"method":"GET"}`,
		"private":       `{"id":"approval.ABC123","scheme":"http","host":"169.254.169.254","port":80,"method":"GET"}`,
		"oversized":     strings.Repeat("x", 4097),
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			policyValue, _ := ghostnetwork.NewPolicyWithApproval("allowlist", nil, []string{"approval.test"})
			request := RunRequest{SessionID: "s", SessionDir: t.TempDir(), NetworkPolicy: policyValue, ApprovalHandler: approvalHandlerFunc(func(context.Context, approval.Request) (approval.Response, error) {
				t.Error("malformed protocol reached approval handler")
				return approval.Response{Scope: approval.AllowSession}, nil
			})}
			paths, err := prepareObservation(request)
			if err != nil {
				t.Fatal(err)
			}
			broker, err := startApprovalBroker(context.Background(), request, paths)
			if err != nil {
				t.Fatal(err)
			}
			publishApprovalFixture(t, paths, "approval.ABC123", payload)
			select {
			case <-broker.done:
			case <-time.After(time.Second):
				_ = broker.stop()
				t.Fatal("broker did not fail closed")
			}
			if err = broker.stop(); err == nil {
				t.Fatal("protocol failure hidden")
			}
			if _, err = os.Stat(filepath.Join(paths.approvalResponses, "approval.ABC123")); !os.IsNotExist(err) {
				t.Fatal("malformed request got a response")
			}
		})
	}
}
