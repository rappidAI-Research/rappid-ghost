package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rappidAI-research/rappid-ghost/internal/config"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	"github.com/rappidAI-research/rappid-ghost/internal/storage"
	"gopkg.in/yaml.v3"
)

// Exercises the same config -> adapter -> manager -> preflight -> Docker exec
// path as a user. With the integration gate enabled, failures must never SKIP.
func TestDockerPythonAdapterWorkflowAndBoundaries(t *testing.T) {
	if os.Getenv("GHOST_DOCKER_INTEGRATION") != "1" {
		t.Skip("set GHOST_DOCKER_INTEGRATION=1 for real Docker")
	}
	ctx := context.Background()
	root := t.TempDir()
	var output, stderr bytes.Buffer
	if err := initProject(ctx, root, &output); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Runtime.Environment = "python"
	cfg.Agent.Adapter = "python"
	cfg.Profile = "coding"
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, config.FileName), data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHOST_HOST_ONLY_SECRET", "HOST_SENTINEL_NOT_FOR_GUEST")
	script := `import os, sys, json, socket, subprocess
from pathlib import Path
assert sys.version_info[:3] == (3,13,18), sys.version
assert os.getuid() != 0
assert 'GHOST_HOST_ONLY_SECRET' not in os.environ
assert not Path('/var/run/docker.sock').exists()
try:
    Path('/workspace/.ghost/ghost.db').open('rb')
except (FileNotFoundError, PermissionError):
    pass
else:
    raise AssertionError('Ghost database readable from guest')
assert sys.argv[1:] == ['hello world', '$(id)']
assert subprocess.check_output([sys.executable, '-c', 'print(6*7)'], text=True).strip() == '42'
try:
    Path('/usr/local/ghost-escape').write_text('bad')
except OSError:
    pass
else:
    raise AssertionError('writable root')
sock=socket.socket(); sock.settimeout(.3)
try:
    sock.connect(('1.1.1.1',443))
except OSError:
    pass
else:
    raise AssertionError('raw network escape')
finally:
    sock.close()
# Exercise the real sentinel with a different agent image.
assert 'GHOST_AWS_' in Path(os.environ['HOME'],'.aws','credentials').read_text()
Path('result.json').write_text(json.dumps({'status':'ok','answer':42}))
print('PYTHON_WORKFLOW_OK')
`
	if err = os.WriteFile(filepath.Join(root, "agent.py"), []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	code := runCommand(ctx, root, []string{"agent.py", "hello world", "$(id)"}, strings.NewReader(""), &output, &stderr)
	if code != 0 || !strings.Contains(output.String(), "PYTHON_WORKFLOW_OK") {
		t.Fatalf("code=%d\n%s\n%s", code, &output, &stderr)
	}
	if result, err := os.ReadFile(filepath.Join(root, "result.json")); err != nil || !strings.Contains(string(result), `"answer": 42`) {
		t.Fatalf("result=%s err=%v", result, err)
	}
	store, err := storage.Open(ctx, filepath.Join(root, config.RuntimeDirName, config.DatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	latest, err := store.LatestSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := store.Events(ctx, latest.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	decoy, contained := false, false
	for _, e := range observed {
		decoy = decoy || e.Type == events.DecoyAccess
		contained = contained || e.Type == events.ContainmentActivated
	}
	if !decoy || !contained {
		t.Fatalf("missing real Python SHADOW/containment evidence: decoy=%t contained=%t", decoy, contained)
	}
	// A second run applies a stricter explicitly selected profile to the same
	// interpreter, preserves existing output and verifies workspace immutability.
	cfg.Profile = "document-processing"
	cfg.Workspace.Mode = "read-only"
	cfg.Policy.Home = "deny"
	data, err = yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, config.FileName), data, 0600); err != nil {
		t.Fatal(err)
	}
	script = `from pathlib import Path
try:
    Path('must-not-exist').write_text('bad')
except OSError:
    print('READ_ONLY_OK')
else:
    raise AssertionError('writable document workspace')
`
	if err = os.WriteFile(filepath.Join(root, "readonly.py"), []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	stderr.Reset()
	if code = runCommand(ctx, root, []string{"readonly.py"}, strings.NewReader(""), &output, &stderr); code != 0 || !strings.Contains(output.String(), "READ_ONLY_OK") {
		t.Fatalf("code=%d %s %s", code, &output, &stderr)
	}
	if _, err = os.Lstat(filepath.Join(root, "must-not-exist")); !os.IsNotExist(err) {
		t.Fatal("read-only profile wrote host workspace")
	}
}
