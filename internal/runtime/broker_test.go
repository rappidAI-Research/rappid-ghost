package runtime

import (
	"encoding/json"
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
