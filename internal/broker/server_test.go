package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixture struct {
	s       *Server
	tls     *httptest.Server
	cfg     Config
	events  []Event
	mu      sync.Mutex
	calls   atomic.Int64
	revoked atomic.Bool
}

func setup(t *testing.T, handler http.HandlerFunc) *fixture {
	t.Helper()
	f := &fixture{}
	f.tls = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if handler != nil {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":"synthetic-only"}`))
	}))
	sum := sha256.Sum256(f.tls.Certificate().Raw)
	endpoint := Endpoint{URL: f.tls.URL, CertificateSHA256: hex.EncodeToString(sum[:]), CredentialEnv: "GHOST_TEST_BROKER_TOKEN"}
	t.Setenv(endpoint.CredentialEnv, "HOST_ONLY_SYNTHETIC_CREDENTIAL")
	f.cfg = Config{Model: &Model{Endpoint: endpoint, Name: "ghost-fixture"}, Application: &endpoint, Tools: []Tool{{Name: "documents.read", Effect: "read", Parameters: map[string]string{"record_id": "string"}, ResourceArgument: "record_id", Resources: []string{"case_A"}}}}
	var err error
	f.s, err = New(context.Background(), f.cfg, Options{Audit: func(_ context.Context, e Event) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.events = append(f.events, e)
		return nil
	}, Check: func(context.Context) error {
		if f.revoked.Load() {
			return errors.New("revoked")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.s.Close(); f.tls.Close() })
	return f
}
func request(s *Server, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Host = "ghost-broker"
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func TestModelBrokerKeepsHostCredentialsOutOfAgentRequestsAndAudit(t *testing.T) {
	var wrong atomic.Bool
	f := setup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer HOST_ONLY_SYNTHETIC_CREDENTIAL" || r.Header.Get("Cookie") != "" || r.URL.Path != "/v1/chat/completions" {
			wrong.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"OK"}}]}`))
	})
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"ghost-fixture","messages":[{"role":"user","content":"SENSITIVE_PROMPT_SENTINEL"}]}`))
	r.Header.Set("Authorization", "Bearer AGENT_CHOSEN_TOKEN")
	r.Header.Set("Cookie", "do-not-forward")
	r.Host = "ghost-broker"
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.s.ServeHTTP(w, r)
	if w.Code != 200 || wrong.Load() || f.calls.Load() != 1 {
		t.Fatalf("status=%d wrong=%t calls=%d", w.Code, wrong.Load(), f.calls.Load())
	}
	data, _ := json.Marshal(f.events)
	for _, secret := range []string{"SENSITIVE_PROMPT_SENTINEL", "HOST_ONLY_SYNTHETIC_CREDENTIAL", "AGENT_CHOSEN_TOKEN", f.tls.URL} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatal("sensitive data in audit")
		}
	}
}
func TestToolsEnforceSchemaResourceScopeAndReplay(t *testing.T) {
	f := setup(t, nil)
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"id":"callA","name":"documents.read","arguments":{"record_id":"case_A"}}`, 200},
		{`{"id":"callA","name":"documents.read","arguments":{"record_id":"case_A"}}`, 409},
		{`{"id":"callB","name":"documents.read","arguments":{"record_id":"case_B"}}`, 403},
		{`{"id":"callC","name":"documents.read","arguments":{"record_id":"case_A","tenant_id":"tenant_B"}}`, 400},
		{`{"id":"callD","name":"documents.delete","arguments":{"record_id":"case_A"}}`, 403},
	} {
		if got := request(f.s, "/ghost/tools/call", tc.body).Code; got != tc.status {
			t.Fatalf("got %d expected %d", got, tc.status)
		}
	}
	if f.calls.Load() != 1 {
		t.Fatal("denied tool reached application")
	}
	data, _ := json.Marshal(f.events)
	if bytes.Contains(data, []byte("case_A")) {
		t.Fatal("resource ID in durable audit")
	}
}
func TestConcurrentReplayConsumesOneInvocation(t *testing.T) {
	f := setup(t, nil)
	var wg sync.WaitGroup
	var successes atomic.Int64
	for range 4 {
		wg.Go(func() {
			if request(f.s, "/ghost/tools/call", `{"id":"sameID","name":"documents.read","arguments":{"record_id":"case_A"}}`).Code == 200 {
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 || f.calls.Load() != 1 {
		t.Fatalf("success=%d upstream=%d", successes.Load(), f.calls.Load())
	}
}
func TestCallerMutationCannotExpandToolCapability(t *testing.T) {
	f := setup(t, nil)
	f.cfg.Tools[0].Resources[0] = "case_B"
	f.cfg.Tools[0].Parameters["tenant"] = "string"
	if request(f.s, "/ghost/tools/call", `{"id":"callA","name":"documents.read","arguments":{"record_id":"case_B"}}`).Code != 403 {
		t.Fatal("caller mutation broadened grant")
	}
	if request(f.s, "/ghost/tools/call", `{"id":"callB","name":"documents.read","arguments":{"record_id":"case_A"}}`).Code != 200 {
		t.Fatal("snapshot lost original grant")
	}
}
func TestMalformedJSONAndRemoteModelToolsFailClosed(t *testing.T) {
	for _, body := range []string{
		`{"model":"ghost-fixture","model":"another"}`, `{"model":"ghost-fixture"} {}`, `{"model":"ghost-fixture","tools":[{"type":"web_search"}]}`,
		`{"model":"ghost-fixture","tools":[{"type":"future_server_tool"}]}`, `{"model":"ghost-fixture","tool_choice":{"type":"mcp","server_label":"remote"}}`, `{"model":"ghost-fixture","tools":[{"type":"tool_search","execution":"server"}]}`, `{"model":"ghost-fixture","input":[{"type":"input_file","file_url":"https://metadata.invalid"}]}`,
		`{"model":"ghost-fixture","previous_response_id":"other-session"}`, `{"model":"ghost-fixture","callback_url":"https://metadata.invalid"}`, `{"model":"ghost-fixture","input":[{"type":"item_reference","id":"foreign"}]}`, `{"model":"ghost-fixture","messages":[{"role":"user","content":[{"type":"future_remote_url","url":"https://metadata.invalid"}]}]}`,
	} {
		t.Run(body, func(t *testing.T) {
			f := setup(t, nil)
			if request(f.s, "/v1/responses", body).Code == 200 || f.calls.Load() != 0 {
				t.Fatal("malformed or privileged request forwarded")
			}
		})
	}
}
func TestAuditFailurePreventsUpstreamEffect(t *testing.T) {
	f := setup(t, nil)
	f.s.options.Audit = func(context.Context, Event) error { return errors.New("storage unavailable") }
	if request(f.s, "/ghost/tools/call", `{"id":"callA","name":"documents.read","arguments":{"record_id":"case_A"}}`).Code != 503 || f.calls.Load() != 0 {
		t.Fatal("effect without durable admission")
	}
}
func TestTLSIdentityAndRedirectsAreNeverBypassed(t *testing.T) {
	t.Run("pin mismatch", func(t *testing.T) {
		f := setup(t, nil)
		cfg := f.cfg.Snapshot()
		cfg.Model.CertificateSHA256 = strings.Repeat("0", 64)
		s, err := New(context.Background(), cfg, f.s.options)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if request(s, "/v1/responses", `{"model":"ghost-fixture","input":"hello"}`).Code != 502 || f.calls.Load() != 0 {
			t.Fatal("server identity mismatch was accepted")
		}
	})
	t.Run("redirect", func(t *testing.T) {
		var targets atomic.Int64
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targets.Add(1) }))
		defer target.Close()
		f := setup(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) })
		if request(f.s, "/v1/responses", `{"model":"ghost-fixture","input":"hello"}`).Code != 502 || targets.Load() != 0 {
			t.Fatal("redirect escaped explicit endpoint")
		}
	})
}
func TestApplicationRevocationAndBrokerExpiryDeny(t *testing.T) {
	f := setup(t, nil)
	f.revoked.Store(true)
	if request(f.s, "/ghost/tools/call", `{"id":"callA","name":"documents.read","arguments":{"record_id":"case_A"}}`).Code != 403 {
		t.Fatal("revocation ignored")
	}
	f.revoked.Store(false)
	if request(f.s, "/ghost/tools/call", `{"id":"callB","name":"documents.read","arguments":{"record_id":"case_A"}}`).Code != 403 {
		t.Fatal("revoked capability reactivated")
	}
}
func TestInFlightContainmentCancelsModelStream(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	f := setup(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: first\n\n"))
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(cancelled)
	})
	done := make(chan struct{})
	go func() {
		request(f.s, "/v1/responses", `{"model":"ghost-fixture","input":"hello","stream":true}`)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("model request not started")
	}
	f.revoked.Store(true)
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("contained model stream remained active")
	}
	<-done
}
func TestDockerSocketLifecycleAndAmbiguousCleanup(t *testing.T) {
	if os.Getenv("GHOST_DOCKER_INTEGRATION") != "1" {
		t.Skip("requires native Linux Unix sockets; exercised by Docker release gate")
	}
	f := setup(t, nil)
	id := "test_" + newID()
	dir, close, err := f.s.ServeUnix(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(filepath.Join(dir, "broker.sock")); err != nil {
		t.Fatal(err)
	}
	if err = close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("socket artifacts remain")
	}
	dir, err = createDirectory(id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(filepath.Join(dir, "other")); os.Remove(filepath.Join(dir, "owner")); os.Remove(dir) })
	if err = os.WriteFile(filepath.Join(dir, "other"), []byte("owned by another component"), 0600); err != nil {
		t.Fatal(err)
	}
	if Cleanup(id) == nil {
		t.Fatal("ambiguous cleanup was accepted")
	}
}
func TestRequestBudgetsAndExpiryAreEnforced(t *testing.T) {
	f := setup(t, nil)
	f.s.cfg.MaxRequests = 1
	if request(f.s, "/v1/responses", `{"model":"ghost-fixture","input":"hello"}`).Code != 200 {
		t.Fatal("first request failed")
	}
	if request(f.s, "/v1/responses", `{"model":"ghost-fixture","input":"hello"}`).Code != 429 || f.calls.Load() != 1 {
		t.Fatal("request budget not enforced")
	}
	f = setup(t, nil)
	f.s.expires = time.Now().Add(25 * time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	if request(f.s, "/v1/responses", `{"model":"ghost-fixture","input":"hello"}`).Code != 403 {
		t.Fatal("expired session allowed")
	}
}
func BenchmarkStrictJSONValidation(b *testing.B) {
	data := []byte(`{"model":"local-model","messages":[{"role":"user","content":"Synthetic benchmark input."}]}`)
	b.ReportAllocs()
	for b.Loop() {
		if err := validJSON(data); err != nil {
			b.Fatal(err)
		}
	}
}

func TestStrictScalarsAndAlternateRoutesCannotExpandCapability(t *testing.T) {
	for _, body := range []string{
		`{"id":"nullA","name":"documents.read","arguments":{"record_id":null}}`,
		`{"id":"nestedA","name":"documents.read","arguments":{"record_id":{"id":"case_A"}}}`,
		`{"id":"extraA","name":"documents.read","arguments":{"record_id":"case_A"},"url":"https://127.0.0.1"}`,
	} {
		f := setup(t, nil)
		if request(f.s, "/ghost/tools/call", body).Code == 200 || f.calls.Load() != 0 {
			t.Fatal("invalid schema reached upstream")
		}
	}
	for _, path := range []string{"/v1/responses?url=https://127.0.0.1", "/v1/../responses", "/v1/%72esponses", "/ghost/admin", "/v1/files", "/v1/models"} {
		f := setup(t, nil)
		if request(f.s, path, `{"model":"ghost-fixture","input":"hello"}`).Code == 200 || f.calls.Load() != 0 {
			t.Fatal("alternate route forwarded")
		}
	}
}
func TestBrokerCapabilitiesDoNotCrossSessions(t *testing.T) {
	a := setup(t, nil)
	b := setup(t, nil)
	b.s.cfg.Tools[0].Resources = []string{"case_B"}
	if request(a.s, "/ghost/tools/call", `{"id":"sameID","name":"documents.read","arguments":{"record_id":"case_A"}}`).Code != 200 {
		t.Fatal("session A denied")
	}
	if request(b.s, "/ghost/tools/call", `{"id":"sameID","name":"documents.read","arguments":{"record_id":"case_A"}}`).Code != 403 {
		t.Fatal("session A grant leaked to B")
	}
	if request(b.s, "/ghost/tools/call", `{"id":"sameID","name":"documents.read","arguments":{"record_id":"case_B"}}`).Code != 200 {
		t.Fatal("session A replay state leaked to B")
	}
}
func TestModelResponsesAreBoundedAndValidateBeforeRelease(t *testing.T) {
	for _, body := range []string{`not-json`, `{"a":1,"a":2}`, strings.Repeat("x", MaxResponseBytes+1)} {
		f := setup(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		})
		out := request(f.s, "/v1/responses", `{"model":"ghost-fixture","input":"hello"}`)
		if out.Code != 502 || strings.Contains(out.Body.String(), body[:min(10, len(body))]) {
			t.Fatal("invalid upstream data released")
		}
	}
}
func TestAuditCorrelatesAdmissionAndCompletion(t *testing.T) {
	f := setup(t, nil)
	if request(f.s, "/ghost/tools/call", `{"id":"clientChosen","name":"documents.read","arguments":{"record_id":"case_A"}}`).Code != 200 {
		t.Fatal("call failed")
	}
	if len(f.events) != 2 || f.events[0].ID != f.events[1].ID || f.events[0].ID == "clientChosen" {
		t.Fatal("missing host-generated request correlation")
	}
}

func TestLocalToolSchemasAreDataNotRemoteMedia(t *testing.T) {
	f := setup(t, nil)
	body := `{"model":"ghost-fixture","input":"hello","tools":[{"type":"function","name":"local_function","parameters":{"type":"object","properties":{"image_url":{"type":"string"}}}},{"type":"tool_search","execution":"client","parameters":{"type":"object"}}]}`
	if result := request(f.s, "/v1/responses", body); result.Code != 200 || f.calls.Load() != 1 {
		t.Fatalf("local definitions rejected: %d %s", result.Code, result.Body.String())
	}
}

func TestPrivateBrokerRootsAreNeverValidWorkspaces(t *testing.T) {
	root, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	id := "workspace_test"
	dir, err := SocketDirectory(id)
	if err != nil {
		t.Fatal(err)
	}
	canonical := filepath.Join(root, filepath.Base(dir))
	for _, path := range []string{root, filepath.Dir(root), canonical, filepath.Join(canonical, "child")} {
		if ValidateWorkspace(path) == nil {
			t.Fatalf("private capability exposure accepted: %s", path)
		}
	}
	if err = ValidateWorkspace(filepath.Join(root, "ordinary-project")); err != nil {
		t.Fatal(err)
	}
}
