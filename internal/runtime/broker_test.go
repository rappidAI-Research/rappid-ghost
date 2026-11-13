package runtime

import (
	"crypto/rand"
	"encoding/json"
	"github.com/rappidAI-research/rappid-ghost/internal/broker"
	"os"
	"testing"
)

func TestBrokerBoundaryRejectsDroppedMountAndNetworkSettings(t *testing.T) {
	base := map[string]any{"HostConfig": map[string]any{"NetworkMode": "none", "Mounts": []any{
		map[string]any{"Type": "bind", "Source": "/trusted/socket", "Target": "/run/ghost-broker", "ReadOnly": true, "BindOptions": map[string]bool{"NonRecursive": true}},
		map[string]any{"Type": "bind", "Source": "/trusted/helper", "Target": "/run/ghost-helper", "ReadOnly": true, "BindOptions": map[string]bool{"NonRecursive": true}}}},
		"Mounts": []any{map[string]any{"Type": "bind", "Source": "/trusted/socket", "Destination": "/run/ghost-broker", "RW": false}, map[string]any{"Type": "bind", "Source": "/trusted/helper", "Destination": "/run/ghost-helper", "RW": false}}}
	data, _ := json.Marshal(base)
	if err := validateBrokerBoundary(data, "/trusted/socket", "/trusted/helper"); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(map[string]any){
		func(v map[string]any) { v["HostConfig"].(map[string]any)["NetworkMode"] = "bridge" },
		func(v map[string]any) { v["Mounts"].([]any)[0].(map[string]any)["RW"] = true },
		func(v map[string]any) {
			v["HostConfig"].(map[string]any)["Mounts"].([]any)[0].(map[string]any)["BindOptions"] = map[string]any{"NonRecursive": false}
		},
		func(v map[string]any) { v["Mounts"].([]any)[1].(map[string]any)["Source"] = "/untrusted/helper" },
	} {
		var changed map[string]any
		json.Unmarshal(data, &changed)
		mutation(changed)
		bad, _ := json.Marshal(changed)
		if validateBrokerBoundary(bad, "/trusted/socket", "/trusted/helper") == nil {
			t.Fatal("invalid boundary retained")
		}
	}
}

func TestPostRunVerificationDoesNotErasePendingBrokerArtifacts(t *testing.T) {
	id := "pending_" + rand.Text()
	directory, err := broker.SocketDirectory(id)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(directory)
	runtime := &DockerRuntime{binary: controlledDocker(t, "exit 0", "exit 0")}
	pending, err := runtime.cleanupPending(id)
	if !pending || err == nil {
		t.Fatal("remaining broker artifact was accepted as clean")
	}
	if _, err = os.Lstat(directory); err != nil {
		t.Fatal("verification silently performed recovery")
	}
}
