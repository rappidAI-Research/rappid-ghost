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
