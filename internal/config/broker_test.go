package config

import (
	"github.com/rappidAI-research/rappid-ghost/internal/broker"
	"testing"
)

func TestBrokerCannotBypassDirectNetworkOrRestrictedProfile(t *testing.T) {
	cfg := Default()
	cfg.Broker.Model = &broker.Model{Endpoint: broker.Endpoint{URL: "https://127.0.0.1:8443"}, Name: "explicit-model"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Network.Mode = "allowlist"
	cfg.Network.Allow = []string{"example.com"}
	if cfg.Validate() == nil {
		t.Fatal("broker allowed direct network bypass")
	}
	cfg.Network = NetworkConfig{Mode: "deny"}
	cfg.Profile = "restricted"
	cfg.Workspace.Mode = "read-only"
	cfg.Policy.Home = "deny"
	if cfg.Validate() == nil {
		t.Fatal("restricted profile permitted broker")
	}
	cfg.Profile = "sensitive-enterprise"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Broker.Tools = []broker.Tool{{Name: "documents.delete", Effect: "write", Parameters: map[string]string{"record_id": "string"}, ResourceArgument: "record_id", Resources: []string{"case_A"}}}
	cfg.Broker.Application = &broker.Endpoint{URL: "https://127.0.0.1:9443", CredentialEnv: "EXPLICIT_APP_KEY"}
	if cfg.Validate() == nil {
		t.Fatal("write-effect tool accepted")
	}
}
