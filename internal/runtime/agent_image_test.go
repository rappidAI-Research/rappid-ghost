package runtime

import (
	"context"
	"encoding/json"
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
