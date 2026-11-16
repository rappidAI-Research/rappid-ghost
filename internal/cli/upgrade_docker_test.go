package cli

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const matchedAgent = `import json,os,time,urllib.request,resource
from pathlib import Path
start=time.perf_counter_ns()
req=urllib.request.Request(os.environ['OPENAI_BASE_URL']+'/responses',data=json.dumps({'model':os.environ['GHOST_MODEL'],'input':'SYNTHETIC_MATCHED_WORKLOAD'}).encode(),headers={'Content-Type':'application/json'})
with urllib.request.urlopen(req,timeout=10) as response:assert json.load(response)['ok']
roundtrip=time.perf_counter_ns()-start
cpu=dict(line.split() for line in Path('/sys/fs/cgroup/cpu.stat').read_text().splitlines())
assert not os.environ.get('GHOST_FIXTURE_UPSTREAM_TOKEN')
assert not os.access('/workspace/.ghost/ghost.db',os.R_OK)
print('MATCHED_METRICS '+json.dumps({'roundtrip_ms':roundtrip/1e6,'guest_process_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'guest_cgroup_peak_bytes':int(Path('/sys/fs/cgroup/memory.peak').read_text()),'guest_cgroup_cpu_usec':int(cpu['usage_usec'])}))
`

func releasedBaseline(t *testing.T) string {
	t.Helper()
	path := os.Getenv("GHOST_BASELINE_BIN")
	if !filepath.IsAbs(path) {
		t.Fatal("required Docker upgrade/performance gate needs GHOST_BASELINE_BIN from scripts/build-v05-baseline.sh")
	}
	out, err := exec.Command(path, "version").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "ghost 0.5.0" {
		t.Fatalf("invalid independent v0.5 baseline: %v %s", err, out)
	}
	return path
}

func TestDockerReleasedV05UpgradeAndMatchedMeasurements(t *testing.T) {
	current := integrationBinary(t)
	baseline := releasedBaseline(t)
	t.Setenv("GHOST_FIXTURE_UPSTREAM_TOKEN", "SYNTHETIC_MATCHED_HOST_SECRET")
	_, endpoint := brokerFixtureEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer SYNTHETIC_MATCHED_HOST_SECRET" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	root := t.TempDir()
	out, err := runIntegrationCLI(t, baseline, root, "init", "--integration", "python", "--profile", "document-processing", "--model-url", endpoint.URL, "--model-name", "matched-fixture", "--credential-env", endpoint.CredentialEnv, "--certificate-sha256", endpoint.CertificateSHA256)
	if err != nil {
		t.Fatalf("released init: %v %s", err, out)
	}
	policyPath := filepath.Join(root, "ghost.yaml")
	originalPolicy, err := os.ReadFile(policyPath)
	if err != nil || bytes.Contains(originalPolicy, []byte("evidence:")) {
		t.Fatal("baseline did not create original v0.5 configuration")
	}
	if err := os.WriteFile(filepath.Join(root, "agent.py"), []byte(matchedAgent), 0600); err != nil {
		t.Fatal(err)
	}
	out, err = runIntegrationCLI(t, baseline, root, "run", "agent.py")
	if err != nil || !strings.Contains(out, "MATCHED_METRICS ") {
		t.Fatalf("released Docker run: %v %s", err, out)
	}
	database := filepath.Join(root, ".ghost", "ghost.db")
	db, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	var version, oldEvents int
	var originalID, originalCommand string
	if err := db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version); err != nil || version != 4 {
		t.Fatalf("not a real v0.5 database: schema=%d err=%v", version, err)
	}
	if err := db.QueryRow("SELECT id,command_json FROM sessions").Scan(&originalID, &originalCommand); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM events WHERE session_id=?", originalID).Scan(&oldEvents); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	out, err = runIntegrationCLI(t, current, root, "run", "agent.py")
	if err != nil || !strings.Contains(out, "MATCHED_METRICS ") {
		t.Fatalf("current upgrade run: %v %s", err, out)
	}
	after, err := os.ReadFile(policyPath)
	if err != nil || !bytes.Equal(originalPolicy, after) {
		t.Fatal("upgrade overwrote the trusted v0.5 policy")
	}
	db, err = sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var retainedCommand string
	var retainedEvents, completed int
	if err := db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version); err != nil || version != 5 {
		t.Fatal("upgrade did not reach the reviewed schema")
	}
	if err := db.QueryRow("SELECT command_json FROM sessions WHERE id=?", originalID).Scan(&retainedCommand); err != nil || retainedCommand != originalCommand {
		t.Fatal("upgrade lost original session identity/command")
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM events WHERE session_id=?", originalID).Scan(&retainedEvents); err != nil || retainedEvents != oldEvents {
		t.Fatal("upgrade changed old session evidence")
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM sessions WHERE status='completed' AND cleanup_pending=0").Scan(&completed); err != nil || completed != 2 {
		t.Fatal("old/new actual Docker sessions were not completed and cleaned")
	}
	_ = db.Close()
	out, err = runIntegrationCLI(t, baseline, root, "inspect")
	if err == nil || !strings.Contains(out, "newer than this Ghost build") {
		t.Fatalf("unsafe implicit database downgrade: %v %s", err, out)
	}
	t.Log("V05_UPGRADE_OK: actual released binary/Docker/schema4 -> current Docker/schema5; policy and old evidence preserved; downgrade refused")

	// Identical original policy, service, agent and prepared images. First-session
	// samples include new project state; registry/image-build cold starts do not.
	roots := []string{t.TempDir(), t.TempDir()}
	for _, directory := range roots {
		if err := os.WriteFile(filepath.Join(directory, "ghost.yaml"), originalPolicy, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "agent.py"), []byte(matchedAgent), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for sample := 0; sample < 4; sample++ {
		for index, binary := range []string{baseline, current} {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			command := exec.CommandContext(ctx, binary, "run", "agent.py")
			command.Dir = roots[index]
			started := time.Now()
			data, err := command.CombinedOutput()
			elapsed := time.Since(started)
			cancel()
			if err != nil {
				t.Fatalf("matched sample failed: %v %s", err, data)
			}
			var metrics map[string]any
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "MATCHED_METRICS ") {
					if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "MATCHED_METRICS ")), &metrics); err != nil {
						t.Fatal(err)
					}
				}
			}
			if metrics == nil {
				t.Fatal("missing actual guest measurements")
			}
			metrics["version"] = []string{"v0.5.0", "v0.6.0-candidate"}[index]
			metrics["sample"] = sample
			metrics["phase"] = "warm"
			if sample == 0 {
				metrics["phase"] = "first-session-prepared-images"
			}
			metrics["wall_ms"] = float64(elapsed.Microseconds()) / 1000
			metrics["controller_cpu_ms"] = float64((command.ProcessState.UserTime() + command.ProcessState.SystemTime()).Microseconds()) / 1000
			usage, ok := command.ProcessState.SysUsage().(*syscall.Rusage)
			if !ok {
				t.Fatal("missing native Linux controller resource accounting")
			}
			metrics["controller_peak_rss_kib"] = usage.Maxrss
			report, _ := json.Marshal(metrics)
			t.Log("VERSION_PERF " + string(report))
		}
	}
}
