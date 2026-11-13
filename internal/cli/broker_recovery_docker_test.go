package cli

import (
	"context"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/broker"
	"github.com/rappidAI-research/rappid-ghost/internal/config"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
)

func TestDockerBrokerCrashRecoveryRemovesStaleSocket(t *testing.T) {
	binary := integrationBinary(t)
	t.Setenv("GHOST_FIXTURE_UPSTREAM_TOKEN", "synthetic-recovery")
	_, endpoint := brokerFixtureEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	cfg := config.Default()
	cfg.Agent.Adapter = "python"
	cfg.Runtime.Environment = "python"
	cfg.Policy.Home = "deny"
	cfg.Broker.Model = &broker.Model{Endpoint: endpoint, Name: "ghost-fixture"}
	root := integrationProject(t, cfg)
	script := `import json,os,time,urllib.request
from pathlib import Path
request=urllib.request.Request(os.environ['OPENAI_BASE_URL']+'/responses',data=json.dumps({'model':os.environ['GHOST_MODEL'],'input':'synthetic recovery'}).encode(),headers={'Content-Type':'application/json'})
with urllib.request.urlopen(request,timeout=5) as response:assert json.load(response)['ok']
Path('ready').write_text('ready')
time.sleep(30)
`
	if err := os.WriteFile(filepath.Join(root, "agent.py"), []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(t.TempDir(), "controller.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command := exec.Command(binary, "run", "agent.py")
	command.Dir = root
	command.Stdout = log
	command.Stderr = log
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	var id string
	defer func() {
		command.Process.Kill()
		command.Wait()
		if id != "" {
			ghruntime.NewDocker().Recover(context.Background(), []string{id})
		}
	}()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if _, err = os.Stat(filepath.Join(root, "ready")); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err = os.Stat(filepath.Join(root, "ready")); err != nil {
		data, _ := os.ReadFile(log.Name())
		t.Fatalf("agent did not start: %v %s", err, data)
	}
	folders, err := os.ReadDir(filepath.Join(root, ".ghost", "sessions"))
	if err != nil || len(folders) != 1 {
		t.Fatal("expected one owned session")
	}
	id = folders[0].Name()
	dir, err := broker.SocketDirectory(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(filepath.Join(dir, "broker.sock")); err != nil {
		t.Fatal("no real broker socket")
	}
	command.Process.Kill()
	command.Wait()
	// The next normal CLI run reconciles its persisted cleanup journal, including
	// the stranded agent container and its exactly owned Unix endpoint.
	if err = os.WriteFile(filepath.Join(root, "next.py"), []byte("print('BROKER_RECOVERY_OK')\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := runIntegrationCLI(t, binary, root, "run", "next.py")
	if err != nil || !strings.Contains(out, "BROKER_RECOVERY_OK") {
		t.Fatalf("recovery %v %s", err, out)
	}
	if _, err = os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("stale broker directory remains")
	}
}

func TestDockerBrokerWarmWorkflowMeasurements(t *testing.T) {
	binary := integrationBinary(t)
	t.Setenv("GHOST_FIXTURE_UPSTREAM_TOKEN", "synthetic-performance")
	_, endpoint := brokerFixtureEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	cfg := config.Default()
	cfg.Agent.Adapter = "python"
	cfg.Runtime.Environment = "python"
	cfg.Policy.Home = "deny"
	root := integrationProject(t, cfg)
	script := `import json,os,time,urllib.request
if 'OPENAI_BASE_URL' in os.environ:
 start=time.perf_counter_ns()
 request=urllib.request.Request(os.environ['OPENAI_BASE_URL']+'/responses',data=json.dumps({'model':os.environ['GHOST_MODEL'],'input':'synthetic performance'}).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(request,timeout=5) as response: assert json.load(response)['ok']
 print('broker_roundtrip_ns='+str(time.perf_counter_ns()-start))
print('PERFORMANCE_WORKFLOW_OK')
`
	if err := os.WriteFile(filepath.Join(root, "agent.py"), []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"baseline", "broker"} {
		if mode == "broker" {
			cfg.Broker.Model = &broker.Model{Endpoint: endpoint, Name: "ghost-fixture"} // YAML is the production policy format.
			writeIntegrationConfig(t, root, cfg)
		}
		for i := 0; i < 4; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			command := exec.CommandContext(ctx, binary, "run", "agent.py")
			command.Dir = root
			start := time.Now()
			out, err := command.CombinedOutput()
			elapsed := time.Since(start)
			cancel()
			if err != nil || !strings.Contains(string(out), "PERFORMANCE_WORKFLOW_OK") {
				t.Fatalf("measurement failed %v %s", err, out)
			}
			if i > 0 {
				t.Logf("warm %s sample=%d wall_ms=%.3f controller_cpu_ms=%.3f controller_resources=%+v output=%s", mode, i, float64(elapsed.Microseconds())/1000, float64((command.ProcessState.UserTime()+command.ProcessState.SystemTime()).Microseconds())/1000, command.ProcessState.SysUsage(), out)
			}
		}
	}
}

func writeIntegrationConfig(t *testing.T, root string, cfg config.Config) {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, config.FileName), data, 0600); err != nil {
		t.Fatal(err)
	}
}
