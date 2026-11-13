package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rappidAI-research/rappid-ghost/examples/enterprise"
	"github.com/rappidAI-research/rappid-ghost/internal/broker"
	"github.com/rappidAI-research/rappid-ghost/internal/config"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	"github.com/rappidAI-research/rappid-ghost/internal/storage"
	"gopkg.in/yaml.v3"
)

func integrationBinary(t *testing.T) string {
	t.Helper()
	if os.Getenv("GHOST_DOCKER_INTEGRATION") != "1" {
		t.Skip("requires real native Linux Docker release gate")
	}
	target := filepath.Join(t.TempDir(), "ghost")
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", target, "./cmd/ghost")
	command.Dir = filepath.Join("..", "..")
	command.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build static CLI: %v %s", err, out)
	}
	return target
}
func integrationProject(t *testing.T, cfg config.Config) string {
	t.Helper()
	root := t.TempDir()
	var out bytes.Buffer
	if err := initProject(context.Background(), root, &out); err != nil {
		t.Fatal(err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, config.FileName), data, 0600); err != nil {
		t.Fatal(err)
	}
	return root
}
func runIntegrationCLI(t *testing.T, binary, root string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, binary, args...)
	command.Dir = root
	output, err := command.CombinedOutput()
	return string(output), err
}
func brokerFixtureEndpoint(t *testing.T, handler http.HandlerFunc) (*httptest.Server, broker.Endpoint) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	sum := sha256.Sum256(server.Certificate().Raw)
	return server, broker.Endpoint{URL: server.URL, CertificateSHA256: hex.EncodeToString(sum[:]), CredentialEnv: "GHOST_FIXTURE_UPSTREAM_TOKEN"}
}
func integrationAudit(t *testing.T, root string) []events.Event {
	t.Helper()
	store, err := storage.Open(context.Background(), filepath.Join(root, ".ghost", "ghost.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s, err := store.LatestSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	list, err := store.Events(context.Background(), s.ID)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// The unmodified pinned official Codex binary performs the real exec/tool loop.
// The model service is deliberately deterministic, not a claim of LLM inference.
func TestDockerRealCodexExecThroughBroker(t *testing.T) {
	binary := integrationBinary(t)
	t.Setenv("GHOST_FIXTURE_UPSTREAM_TOKEN", "HOST_CREDENTIAL_MUST_NOT_ENTER_GUEST")
	var calls atomic.Int64
	var toolOutput atomic.Bool
	_, endpoint := brokerFixtureEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer HOST_CREDENTIAL_MUST_NOT_ENTER_GUEST" {
			http.Error(w, "wrong route or credential", 403)
			return
		}
		var body map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "bad JSON", 400)
			return
		}
		n := calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		send := func(value any) {
			data, _ := json.Marshal(value)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", value.(map[string]any)["type"], data)
		}
		send(map[string]any{"type": "response.created", "response": map[string]any{"id": fmt.Sprint("resp_", n)}})
		if n == 1 {
			if !bytes.Contains(body["tools"], []byte(`"exec_command"`)) {
				t.Errorf("real Codex did not advertise exec_command: %s", body["tools"])
			}
			args, _ := json.Marshal(map[string]any{"cmd": "printf 'Hello from the real Codex CLI\\n' > generated.txt; printf 'EXECUTED_IN_GHOST\\n'; test -z \"$GHOST_FIXTURE_UPSTREAM_TOKEN\"", "login": false, "yield_time_ms": 1000})
			send(map[string]any{"type": "response.output_item.done", "item": map[string]any{"type": "function_call", "call_id": "call_ghost_1", "name": "exec_command", "arguments": string(args)}})
		} else {
			toolOutput.Store(bytes.Contains(body["input"], []byte("EXECUTED_IN_GHOST")) && bytes.Contains(body["input"], []byte("function_call_output")))
			send(map[string]any{"type": "response.output_item.done", "item": map[string]any{"type": "message", "role": "assistant", "id": "msg_ghost", "content": []any{map[string]string{"type": "output_text", "text": "Created generated.txt inside Ghost."}}}})
		}
		send(map[string]any{"type": "response.completed", "response": map[string]any{"id": fmt.Sprint("resp_", n), "usage": map[string]any{"input_tokens": 10, "output_tokens": 10, "total_tokens": 20}}})
	})
	cfg := config.Default()
	cfg.Agent.Adapter = "codex"
	cfg.Runtime.Environment = "codex"
	cfg.Profile = "coding"
	cfg.Policy.Home = "deny"
	cfg.Broker.Model = &broker.Model{Endpoint: endpoint, Name: "ghost-fixture"}
	root := integrationProject(t, cfg)
	started := time.Now()
	out, err := runIntegrationCLI(t, binary, root, "run", "Create generated.txt, then report success.")
	t.Logf("real Codex cold workflow elapsed=%s", time.Since(started))
	if err != nil || calls.Load() != 2 || !toolOutput.Load() {
		t.Fatalf("Codex err=%v calls=%d toolOutput=%t\n%s", err, calls.Load(), toolOutput.Load(), out)
	}
	data, err := os.ReadFile(filepath.Join(root, "generated.txt"))
	if err != nil || !strings.Contains(string(data), "Hello from the real Codex CLI") {
		t.Fatalf("real tool output %q %v", data, err)
	}
	audit := integrationAudit(t, root)
	encoded, _ := json.Marshal(audit)
	if bytes.Contains(encoded, []byte("HOST_CREDENTIAL_MUST_NOT_ENTER_GUEST")) || bytes.Contains(encoded, []byte("Create generated.txt")) {
		t.Fatal("credential or prompt persisted")
	}
	admitted, completed := 0, 0
	for _, e := range audit {
		if e.Type == events.BrokerAdmission {
			admitted++
		}
		if e.Type == events.BrokerCompleted {
			completed++
		}
	}
	if admitted != 2 || completed != 2 {
		t.Fatalf("missing durable model decisions admitted=%d completed=%d", admitted, completed)
	}
}

func TestDockerNodeAdapterBoundary(t *testing.T) {
	if os.Getenv("GHOST_DOCKER_INTEGRATION") != "1" {
		t.Skip("requires real Docker")
	}
	cfg := config.Default()
	cfg.Agent.Adapter = "node"
	cfg.Runtime.Environment = "node"
	cfg.Profile = "coding"
	root := integrationProject(t, cfg)
	t.Setenv("HOST_NODE_SECRET", "not-for-agent")
	script := `const fs=require('node:fs');const assert=require('node:assert/strict');const net=require('node:net');
assert.equal(process.version,'v24.22.3');assert.notEqual(process.getuid(),0);assert.equal(process.env.HOST_NODE_SECRET,undefined);
assert.throws(()=>fs.writeFileSync('/usr/local/root-escape','bad'));assert.throws(()=>fs.readFileSync('/workspace/.ghost/ghost.db'));
assert.throws(()=>fs.accessSync('/usr/local/bin/npm'));assert.throws(()=>fs.accessSync('/usr/local/bin/yarn'));
assert.deepEqual(process.argv.slice(2),['hello world','$(id)']);
const socket=net.connect({host:'1.1.1.1',port:443});socket.setTimeout(300);socket.once('connect',()=>{throw Error('network bypass')});
socket.once('error',()=>{fs.writeFileSync('node-result.json',JSON.stringify({status:'ok',answer:42}));console.log('NODE_BOUNDARY_OK')});socket.once('timeout',()=>socket.destroy(Error('timeout')));`
	if err := os.WriteFile(filepath.Join(root, "agent.cjs"), []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runCommand(context.Background(), root, []string{"agent.cjs", "hello world", "$(id)"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "NODE_BOUNDARY_OK") {
		t.Fatalf("code=%d %s %s", code, &stdout, &stderr)
	}
}

func TestDockerBrokerSyntheticEnterpriseAndRevocation(t *testing.T) {
	binary := integrationBinary(t)
	t.Setenv("GHOST_FIXTURE_UPSTREAM_TOKEN", "employee_A_tenant_A")
	var appCalls atomic.Int64
	var modelCalls atomic.Int64
	app := enterprise.New("employee_A_tenant_A")
	_, endpoint := brokerFixtureEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions" {
			modelCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"choices":[{"message":{"content":"Synthetic summary"}}]}`)
			return
		}
		appCalls.Add(1)
		app.ServeHTTP(w, r)
		if app.SuccessfulReads() == 2 {
			app.Revoke()
		}
	})
	cfg := config.Default()
	cfg.Agent.Adapter = "python"
	cfg.Runtime.Environment = "python"
	cfg.Profile = "sensitive-enterprise"
	cfg.Policy.Home = "deny"
	cfg.Workspace.Mode = "read-only"
	cfg.Broker = broker.Config{Model: &broker.Model{Endpoint: endpoint, Name: "ghost-fixture"}, Application: &endpoint, Tools: []broker.Tool{{Name: "documents.read", Effect: "read", Parameters: map[string]string{"record_id": "string"}, ResourceArgument: "record_id", Resources: []string{"case_A", "case_B", "tenant_B_case_C"}}}}
	// Broader configured grants deliberately test the APPLICATION authorization
	// boundary as well as Ghost's independent schema/tool restrictions.
	root := integrationProject(t, cfg)
	script := `import os,json,socket,urllib.request,urllib.error
assert 'GHOST_FIXTURE_UPSTREAM_TOKEN' not in os.environ
base=os.environ['GHOST_BROKER_URL']
def call(path,body,expected=200):
 req=urllib.request.Request(base+path,data=json.dumps(body).encode(),headers={'Content-Type':'application/json'})
 try:
  with urllib.request.urlopen(req,timeout=5) as response: assert expected==200;return json.load(response)
 except urllib.error.HTTPError as error: assert error.code==expected,(error.code,expected,error.read());return {}
doc=call('/ghost/tools/call',{'id':'readA','name':'documents.read','arguments':{'record_id':'case_A'}})
assert 'SYNTHETIC' in doc['document']
call('/v1/chat/completions',{'model':os.environ['GHOST_MODEL'],'messages':[{'role':'user','content':doc['document']}]})
call('/ghost/tools/call',{'id':'readB','name':'documents.read','arguments':{'record_id':'case_B'}},403)
call('/ghost/tools/call',{'id':'readC','name':'documents.read','arguments':{'record_id':'tenant_B_case_C'}},403)
call('/ghost/tools/call',{'id':'before_revoke','name':'documents.read','arguments':{'record_id':'case_A'}})
call('/ghost/tools/call',{'id':'again','name':'documents.read','arguments':{'record_id':'case_A'}},403)
call('/ghost/tools/call',{'id':'delete','name':'documents.delete','arguments':{'record_id':'case_A'}},403)
s=socket.socket();s.settimeout(.3)
try:s.connect(('1.1.1.1',443))
except OSError:pass
else:raise AssertionError('external network bypass')
finally:s.close()
print('ENTERPRISE_BOUNDARIES_OK')
`
	if err := os.WriteFile(filepath.Join(root, "agent.py"), []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	out, err := runIntegrationCLI(t, binary, root, "run", "agent.py")
	t.Logf("enterprise broker workflow elapsed=%s", time.Since(started))
	if err != nil || !strings.Contains(out, "ENTERPRISE_BOUNDARIES_OK") || appCalls.Load() != 5 || modelCalls.Load() != 1 {
		t.Fatalf("err=%v app=%d model=%d\n%s", err, appCalls.Load(), modelCalls.Load(), out)
	}
	encoded, _ := json.Marshal(integrationAudit(t, root))
	for _, secret := range []string{"employee_A_tenant_A", "SYNTHETIC CASE A", "tenant_B_case_C"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("audit leaked %s", secret)
		}
	}
}

func TestDockerBrokerDecoyFenceCannotBeBypassed(t *testing.T) {
	binary := integrationBinary(t)
	t.Setenv("GHOST_FIXTURE_UPSTREAM_TOKEN", "fixture-only")
	var calls atomic.Int64
	_, endpoint := brokerFixtureEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	})
	cfg := config.Default()
	cfg.Agent.Adapter = "python"
	cfg.Runtime.Environment = "python"
	cfg.Broker.Model = &broker.Model{Endpoint: endpoint, Name: "ghost-fixture"}
	root := integrationProject(t, cfg)
	script := `import os,json,urllib.request,urllib.error
from pathlib import Path
assert 'GHOST_AWS_' in Path(os.environ['HOME'],'.aws','credentials').read_text()
req=urllib.request.Request(os.environ['OPENAI_BASE_URL']+'/responses',data=json.dumps({'model':os.environ['GHOST_MODEL'],'input':'must never leave'}).encode(),headers={'Content-Type':'application/json'})
try:urllib.request.urlopen(req,timeout=5)
except urllib.error.HTTPError as e:assert e.code==403,e.code;print('BROKER_CONTAINMENT_OK')
else:raise AssertionError('contained model access')
`
	if err := os.WriteFile(filepath.Join(root, "agent.py"), []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	out, _ := runIntegrationCLI(t, binary, root, "run", "agent.py")
	if calls.Load() != 0 || !strings.Contains(out, "BROKER_CONTAINMENT_OK") {
		t.Fatalf("containment bypass calls=%d\n%s", calls.Load(), out)
	}
}

func TestDockerOfficialMCPClientCannotBypassScope(t *testing.T) {
	binary := integrationBinary(t)
	t.Setenv("GHOST_FIXTURE_UPSTREAM_TOKEN", "trusted_employee_A")
	var calls atomic.Int64
	_, endpoint := brokerFixtureEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ghost/tools/call" || r.Header.Get("Authorization") != "Bearer trusted_employee_A" {
			http.Error(w, "unauthorized", 403)
			return
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"document":"Synthetic record A only."}`)
	})
	cfg := config.Default()
	cfg.Profile = "sensitive-enterprise"
	cfg.Policy.Home = "deny"
	cfg.Workspace.Mode = "read-only"
	cfg.Broker = broker.Config{Application: &endpoint, Tools: []broker.Tool{{Name: "documents.read", Effect: "read", Parameters: map[string]string{"record_id": "string"}, ResourceArgument: "record_id", Resources: []string{"case_A"}}}}
	root := integrationProject(t, cfg)
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", filepath.Join(root, "mcp-agent"), "./examples/mcp-agent")
	command.Dir = filepath.Join("..", "..")
	command.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build actual MCP SDK agent %v %s", err, out)
	}
	out, err := runIntegrationCLI(t, binary, root, "run", "/workspace/mcp-agent")
	if err != nil || calls.Load() != 1 || !strings.Contains(out, "MCP_SCOPE_OK") {
		t.Fatalf("MCP SDK guest err=%v calls=%d\n%s", err, calls.Load(), out)
	}
}

func TestDockerRealLocalModelInference(t *testing.T) {
	binary := integrationBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "sh", filepath.Join("..", "..", "scripts", "test-local-model.sh"))
	command.Env = append(os.Environ(), "GHOST_BIN="+binary)
	started := time.Now()
	out, err := command.CombinedOutput()
	t.Logf("real local inference qualification elapsed=%s", time.Since(started))
	if err != nil || !bytes.Contains(out, []byte("LOCAL_INFERENCE_OK")) {
		t.Fatalf("local inference qualification %v\n%s", err, out)
	}
	t.Logf("%s", out)
}

func TestDockerBrokerConcurrentSessionScopesStaySeparate(t *testing.T) {
	binary := integrationBinary(t)
	t.Setenv("GHOST_SESSION_A_TOKEN", "synthetic_A")
	t.Setenv("GHOST_SESSION_B_TOKEN", "synthetic_B")
	var calls atomic.Int64
	arrived := make(chan struct{})
	_, endpoint := brokerFixtureEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		var call struct {
			Arguments map[string]string `json:"arguments"`
		}
		if json.NewDecoder(r.Body).Decode(&call) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		expected := "Bearer synthetic_A"
		if call.Arguments["record_id"] == "case_B" {
			expected = "Bearer synthetic_B"
		}
		if r.Header.Get("Authorization") != expected {
			http.Error(w, "identity crossed sessions", 403)
			return
		}
		if calls.Add(1) == 2 {
			close(arrived)
		}
		select {
		case <-arrived:
		case <-r.Context().Done():
			return
		case <-time.After(5 * time.Second):
			http.Error(w, "sessions not concurrent", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	roots := make([]string, 2)
	for i, record := range []string{"case_A", "case_B"} {
		cfg := config.Default()
		cfg.Agent.Adapter = "python"
		cfg.Runtime.Environment = "python"
		cfg.Policy.Home = "deny"
		service := endpoint
		service.CredentialEnv = []string{"GHOST_SESSION_A_TOKEN", "GHOST_SESSION_B_TOKEN"}[i]
		cfg.Broker = broker.Config{Application: &service, Tools: []broker.Tool{{Name: "documents.read", Effect: "read", Parameters: map[string]string{"record_id": "string"}, ResourceArgument: "record_id", Resources: []string{record}}}}
		roots[i] = integrationProject(t, cfg)
		script := `import os,sys,json,urllib.request,urllib.error
base=os.environ['GHOST_BROKER_URL']
def call(record,request_id):
 request=urllib.request.Request(base+'/ghost/tools/call',data=json.dumps({'id':request_id,'name':'documents.read','arguments':{'record_id':record}}).encode(),headers={'Content-Type':'application/json'})
 return urllib.request.urlopen(request,timeout=10)
with call(sys.argv[1],'sameID') as response:assert json.load(response)['ok']
try:call(sys.argv[2],'otherID')
except urllib.error.HTTPError as error:assert error.code==403
else:raise AssertionError('cross-session grant')
print('CONCURRENT_SCOPE_OK')
`
		if err := os.WriteFile(filepath.Join(roots[i], "agent.py"), []byte(script), 0600); err != nil {
			t.Fatal(err)
		}
	}
	type result struct {
		out string
		err error
	}
	results := make(chan result, 2)
	for i, root := range roots {
		go func() {
			records := []string{"case_A", "case_B"}
			out, err := runIntegrationCLI(t, binary, root, "run", "agent.py", records[i], records[1-i])
			results <- result{out, err}
		}()
	}
	for range 2 {
		r := <-results
		if r.err != nil || !strings.Contains(r.out, "CONCURRENT_SCOPE_OK") {
			t.Fatalf("parallel scope %v %s", r.err, r.out)
		}
	}
	if calls.Load() != 2 {
		t.Fatal("foreign request reached service")
	}
}
