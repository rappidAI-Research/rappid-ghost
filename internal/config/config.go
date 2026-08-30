package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	FileName       = "ghost.yaml"
	RuntimeDirName = ".ghost"
	DatabaseName   = "ghost.db"
	SessionsDir    = "sessions"
)

type Config struct {
	Version   int             `yaml:"version"`
	Runtime   RuntimeConfig   `yaml:"runtime"`
	Workspace WorkspaceConfig `yaml:"workspace"`
	Network   NetworkConfig   `yaml:"network"`
	Policy    PolicyConfig    `yaml:"policy"`
}

type RuntimeConfig struct {
	Provider string `yaml:"provider"`
}

type WorkspaceConfig struct {
	Mode string `yaml:"mode"`
}

type NetworkConfig struct {
	Mode string `yaml:"mode"`
}

type PolicyConfig struct {
	Home string `yaml:"home"`
}

func Default() Config {
	return Config{
		Version:   1,
		Runtime:   RuntimeConfig{Provider: "docker"},
		Workspace: WorkspaceConfig{Mode: "read-write"},
		Network:   NetworkConfig{Mode: "none"},
		Policy:    PolicyConfig{Home: "deny"},
	}
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse configuration: %w", err)
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
	if c.Network.Mode != "none" {
		return fmt.Errorf("invalid configuration: network.mode must be none in this release")
	}
	if c.Policy.Home != "deny" {
		return fmt.Errorf("invalid configuration: policy.home must be deny in this release")
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
