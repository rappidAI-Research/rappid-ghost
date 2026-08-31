package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
	"gopkg.in/yaml.v3"
)

const (
	FileName       = "ghost.yaml"
	RuntimeDirName = ".ghost"
	DatabaseName   = "ghost.db"
	SessionsDir    = "sessions"
)

type Config struct {
	Version       int               `yaml:"version"`
	Runtime       RuntimeConfig     `yaml:"runtime"`
	Workspace     WorkspaceConfig   `yaml:"workspace"`
	Network       NetworkConfig     `yaml:"network"`
	Policy        PolicyConfig      `yaml:"policy"`
	Deception     DeceptionConfig   `yaml:"deception"`
	OnDecoyAccess DecoyAccessConfig `yaml:"on_decoy_access"`
}

type RuntimeConfig struct {
	Provider string `yaml:"provider"`
}

type WorkspaceConfig struct {
	Mode string `yaml:"mode"`
}

type NetworkConfig struct {
	Mode  string   `yaml:"mode"`
	Allow []string `yaml:"allow,omitempty"`
}

type PolicyConfig struct {
	Home string `yaml:"home"`
}

type DeceptionConfig struct {
	Enabled   bool                     `yaml:"enabled"`
	Resources DeceptionResourcesConfig `yaml:"resources"`
}

type DeceptionResourcesConfig struct {
	AWSCredentials bool `yaml:"aws_credentials"`
	SSHPrivateKey  bool `yaml:"ssh_private_key"`
	EnvFile        bool `yaml:"env_file"`
}

type DecoyAccessConfig struct {
	Severity       string `yaml:"severity"`
	RecordIncident bool   `yaml:"record_incident"`
	Network        string `yaml:"network"`
}

func Default() Config {
	return Config{
		Version:   1,
		Runtime:   RuntimeConfig{Provider: "docker"},
		Workspace: WorkspaceConfig{Mode: "read-write"},
		Network:   NetworkConfig{Mode: string(ghostnetwork.Deny)},
		Policy:    PolicyConfig{Home: "shadow"},
		Deception: DeceptionConfig{
			Enabled: true,
			Resources: DeceptionResourcesConfig{
				AWSCredentials: true,
				SSHPrivateKey:  true,
				EnvFile:        true,
			},
		},
		OnDecoyAccess: DecoyAccessConfig{
			Severity:       "high",
			RecordIncident: true,
			Network:        "deny",
		},
	}
}

func Load(path string) (Config, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Config{}, errors.New("read configuration: ghost.yaml must be a regular file, not a symlink")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	cfg := Default()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse configuration: %w", err)
	}
	if cfg.Network.Mode == "none" {
		cfg.Network.Mode = string(ghostnetwork.Deny)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("parse configuration: multiple YAML documents are not supported")
		}
		return Config{}, fmt.Errorf("parse configuration: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("invalid configuration: version must be 1")
	}
	if c.Runtime.Provider != "docker" {
		return fmt.Errorf("invalid configuration: runtime.provider must be docker")
	}
	if c.Workspace.Mode != "read-write" && c.Workspace.Mode != "read-only" {
		return fmt.Errorf("invalid configuration: workspace.mode must be read-write or read-only")
	}
	if _, err := ghostnetwork.NewPolicy(c.Network.Mode, c.Network.Allow); err != nil {
		return fmt.Errorf("invalid configuration: network: %w", err)
	}
	if c.Policy.Home != "deny" && c.Policy.Home != "shadow" {
		return fmt.Errorf("invalid configuration: policy.home must be deny or shadow")
	}
	if c.OnDecoyAccess.Severity != "low" && c.OnDecoyAccess.Severity != "medium" && c.OnDecoyAccess.Severity != "high" {
		return fmt.Errorf("invalid configuration: on_decoy_access.severity must be low, medium, or high")
	}
	if c.OnDecoyAccess.Network != "deny" && c.OnDecoyAccess.Network != "unchanged" {
		return fmt.Errorf("invalid configuration: on_decoy_access.network must be deny or unchanged")
	}
	return nil
}

// WriteDefault uses O_EXCL so initialization can never overwrite project policy.
func WriteDefault(path string) (bool, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("create configuration: %w", err)
	}

	data, err := yaml.Marshal(Default())
	if err == nil {
		_, err = file.Write(data)
	}
	closeErr := file.Close()
	if err != nil {
		_ = os.Remove(path)
		return false, fmt.Errorf("write configuration: %w", err)
	}
	if closeErr != nil {
		return false, fmt.Errorf("close configuration: %w", closeErr)
	}
	return true, nil
}
