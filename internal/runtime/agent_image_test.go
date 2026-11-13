package runtime

import (
	"context"
	"encoding/json"
	"github.com/rappidAI-research/rappid-ghost/internal/compat"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogImageRejectsImageSideEffects(t *testing.T) {
	root := t.TempDir()
	metadata := filepath.Join(root, "metadata")
	binary := filepath.Join(root, "docker")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\ncat '"+metadata+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		config map[string]any
		valid  bool
	}{
		{"safe", map[string]any{}, true},
		{"volume", map[string]any{"Volumes": map[string]any{"/workspace": map[string]any{}}}, false},
		{"entrypoint", map[string]any{"Entrypoint": []string{"/evil"}}, false},
		{"healthcheck", map[string]any{"Healthcheck": map[string]any{"Test": []string{"CMD", "bad"}}}, false},
		{"onbuild", map[string]any{"OnBuild": []string{"RUN bad"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := json.Marshal(map[string]any{"Id": "sha256:" + strings.Repeat("a", 64), "Os": "linux", "Config": tc.config})
			if err := os.WriteFile(metadata, data, 0600); err != nil {
				t.Fatal(err)
			}
			id, err := (&DockerRuntime{binary: binary}).validateAgentImage(context.Background(), "catalog-image")
			if (err == nil) != tc.valid || (tc.valid && !imageIDPattern.MatchString(id)) {
				t.Fatalf("%s %v", id, err)
			}
		})
	}
}

func TestUnknownEnvironmentFailsBeforeDocker(t *testing.T) {
	_, err := NewDockerWithOptions(DockerOptions{Binary: "must-not-run"}).Preflight(context.Background(), RunRequest{Command: []string{"true"}, Environment: "host"})
	if err == nil || !strings.Contains(err.Error(), "unsupported runtime.environment") {
		t.Fatal(err)
	}
}

func TestCreatedContainerBoundaryRejectsPrivilegeChanges(t *testing.T) {
	base := map[string]any{"Memory": int64(2048 * 1024 * 1024), "MemorySwap": int64(2048 * 1024 * 1024), "CPUPeriod": 100000, "CPUQuota": 100000, "PidsLimit": 256, "ReadonlyRootfs": true, "CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges"}, "IpcMode": "private", "CgroupnsMode": "private", "LogConfig": map[string]any{"Type": "none"}, "Ulimits": []map[string]any{{"Name": "core", "Soft": 0, "Hard": 0}}}
	raw, _ := json.Marshal(base)
	if err := validateContainerBoundary(raw, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]any{"Privileged": true, "CapAdd": []string{"SYS_ADMIN"}, "CapDrop": []string{}, "SecurityOpt": []string{"no-new-privileges=false"}, "PidMode": "host", "IpcMode": "host", "CgroupnsMode": "host", "UsernsMode": "host", "NetworkMode": "host", "Devices": []string{"device"}, "DeviceRequests": []string{"gpu"}, "PublishAllPorts": true, "Ulimits": []string{}, "LogConfig": map[string]any{"Type": "json-file"}} {
		t.Run(key, func(t *testing.T) {
			copy := map[string]any{}
			for k, v := range base {
				copy[k] = v
			}
			copy[key] = value
			raw, _ := json.Marshal(copy)
			if validateContainerBoundary(raw, DefaultLimits()) == nil {
				t.Fatalf("accepted weakened %s", key)
			}
		})
	}
}

func TestDockerPythonTimeoutRetainsResourceBoundaryAndCleanup(t *testing.T) {
	requireResourceDocker(t)
	request := resourceDockerRequest(t)
	request.Environment = "python"
	request.Limits.TimeoutSeconds = 4
	request.Command = []string{"/usr/local/bin/python3", "-c", `import subprocess,sys,time
subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])
time.sleep(60)`}
	result, err := NewDocker().Run(context.Background(), request)
	if err == nil || !result.Started || !hasResource(result, ResourceTimeout) {
		t.Fatalf("missing Python timeout evidence: %+v %v", result, err)
	}
	assertAgentRemoved(t, request)
}

func TestReviewedImageBuildHasNoProjectContextOrNetwork(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "docker")
	input := filepath.Join(root, "recipe")
	argsFile := filepath.Join(root, "arguments")
	id := "sha256:" + strings.Repeat("a", 64)
	script := `#!/bin/sh
case "$1" in
 image)
  if [ "$3" = '--format' ]; then printf '%s\n' '{"Id":"` + id + `","Os":"linux","Config":{}}'; fi
  ;;
 build)
  printf '%s\n' "$@" > '` + argsFile + `'
  cat > '` + input + `'
  test "$DOCKER_BUILDKIT" = 1 || exit 42
  printf '%s\n' '` + id + `'
  ;;
 *) exit 1 ;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	environment, err := compat.ResolveEnvironment("python")
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&DockerRuntime{binary: binary}).prepareDerivedImage(context.Background(), environment)
	if err != nil || got != id {
		t.Fatalf("%s %v", got, err)
	}
	args, _ := os.ReadFile(argsFile)
	recipe, _ := os.ReadFile(input)
	if !strings.Contains(string(args), "--network\nnone\n") || !strings.HasSuffix(string(args), "-\n") || strings.Contains(string(args), root) || !strings.HasPrefix(string(recipe), "FROM "+compat.PythonImage+"\n") {
		t.Fatalf("unsafe reviewed build: %s %s", args, recipe)
	}
}
