package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsInvalidValuesAndUnknownFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
	}{
		{"runtime", "version: 1\nruntime: {provider: host}\nworkspace: {mode: read-write}\nnetwork: {mode: none}\npolicy: {home: deny}\n"},
		{"workspace", "version: 1\nruntime: {provider: docker}\nworkspace: {mode: magic}\nnetwork: {mode: none}\npolicy: {home: deny}\n"},
		{"network", "version: 1\nruntime: {provider: docker}\nworkspace: {mode: read-write}\nnetwork: {mode: host}\npolicy: {home: deny}\n"},
		{"home", "version: 1\nruntime: {provider: docker}\nworkspace: {mode: read-write}\nnetwork: {mode: none}\npolicy: {home: allow}\n"},
		{"severity", "version: 1\nruntime: {provider: docker}\nworkspace: {mode: read-write}\nnetwork: {mode: none}\npolicy: {home: shadow}\non_decoy_access: {severity: critical}\n"},
		{"unknown", "version: 1\nruntime: {provider: docker}\nworkspace: {mode: read-write}\nnetwork: {mode: none}\npolicy: {home: deny}\nsurprise: true\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), FileName)
			if err := os.WriteFile(path, []byte(tt.yaml), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load accepted invalid configuration")
			}
		})
	}
}

func TestLoadPreservesExplicitlyDisabledDeception(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), FileName)
	data := "version: 1\nruntime: {provider: docker}\nworkspace: {mode: read-write}\nnetwork: {mode: none}\npolicy: {home: shadow}\ndeception: {enabled: false}\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Deception.Enabled {
		t.Fatal("explicit deception.enabled=false was replaced by a default")
	}
}

func TestWriteDefaultDoesNotOverwrite(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), FileName)
	created, err := WriteDefault(path)
	if err != nil || !created {
		t.Fatalf("first WriteDefault = %v, %v", created, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "provider: docker") {
		t.Fatalf("unexpected default configuration: %s", data)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("default configuration is invalid: %v", err)
	}

	if err := os.WriteFile(path, []byte("custom: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	created, err = WriteDefault(path)
	if err != nil || created {
		t.Fatalf("second WriteDefault = %v, %v", created, err)
	}
	data, _ = os.ReadFile(path)
	if string(data) != "custom: true\n" {
		t.Fatalf("existing configuration was overwritten: %s", data)
	}
}

func TestDefaultEnablesDocumentedShadowResources(t *testing.T) {
	t.Parallel()

	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Default().Validate() error = %v", err)
	}
	if cfg.Policy.Home != "shadow" || !cfg.Deception.Enabled {
		t.Fatalf("unexpected Shadow defaults: %+v", cfg)
	}
	if !cfg.Deception.Resources.AWSCredentials || !cfg.Deception.Resources.SSHPrivateKey || !cfg.Deception.Resources.EnvFile {
		t.Fatalf("unexpected resource defaults: %+v", cfg.Deception.Resources)
	}
}

func TestLoadOldDenyConfigurationUsesSafeDefaults(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), FileName)
	data := "version: 1\nruntime: {provider: docker}\nworkspace: {mode: read-write}\nnetwork: {mode: none}\npolicy: {home: deny}\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Policy.Home != "deny" || !cfg.Deception.Enabled || cfg.Network.Mode != "deny" {
		t.Fatalf("unexpected migrated configuration: %+v", cfg)
	}
}

func TestNetworkModesAndAllowlistParsing(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		network  string
		wantMode string
		wantErr  bool
	}{
		{"default deny", "", "deny", false},
		{"explicit deny", "network: {mode: deny}\n", "deny", false},
		{"allowlist", "network:\n  mode: allowlist\n  allow: [example.com, API.EXAMPLE.COM.]\n", "allowlist", false},
		{"empty allowlist", "network: {mode: allowlist}\n", "", true},
		{"raw IP", "network: {mode: allowlist, allow: [127.0.0.1]}\n", "", true},
		{"wildcard", "network: {mode: allowlist, allow: ['*.example.com']}\n", "", true},
		{"deny with allow entries", "network: {mode: deny, allow: [example.com]}\n", "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), FileName)
			data := "version: 1\nruntime: {provider: docker}\nworkspace: {mode: read-write}\npolicy: {home: deny}\n" + test.network
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if test.wantErr {
				if err == nil {
					t.Fatalf("Load() succeeded: %+v", cfg)
				}
				return
			}
			if err != nil || cfg.Network.Mode != test.wantMode {
				t.Fatalf("Load() = %+v, %v", cfg, err)
			}
		})
	}
}

func TestDefaultNetworkFailsClosedAndContainsAfterDecoy(t *testing.T) {
	cfg := Default()
	if cfg.Network.Mode != "deny" || len(cfg.Network.Allow) != 0 {
		t.Fatalf("unsafe default network: %+v", cfg.Network)
	}
	if cfg.OnDecoyAccess.Network != "deny" {
		t.Fatalf("default containment = %q", cfg.OnDecoyAccess.Network)
	}
}
