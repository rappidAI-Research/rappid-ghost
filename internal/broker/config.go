// Package broker mediates explicit per-session model and read-tool capabilities.
// It never derives permissions from project text, model output or tool metadata.
package broker

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type Endpoint struct {
	URL               string `yaml:"url" json:"-"`
	CertificateSHA256 string `yaml:"certificate_sha256,omitempty" json:"-"`
	CredentialEnv     string `yaml:"credential_env,omitempty" json:"-"`
}

type Model struct {
	Endpoint        `yaml:",inline"`
	Name            string `yaml:"name"`
	MaxOutputTokens int    `yaml:"max_output_tokens,omitempty"`
}

type Tool struct {
	Name             string            `yaml:"name"`
	Parameters       map[string]string `yaml:"parameters"`
	ResourceArgument string            `yaml:"resource_argument"`
	Resources        []string          `yaml:"resources"`
}

type Config struct {
	Model       *Model    `yaml:"model,omitempty"`
	Application *Endpoint `yaml:"application,omitempty"`
	Tools       []Tool    `yaml:"tools,omitempty"`
	TTLSeconds  int       `yaml:"ttl_seconds,omitempty"`
	MaxRequests int       `yaml:"max_requests,omitempty"`
}

var modelPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}$`)
var namePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{0,63}$`)
var envPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (c Config) Enabled() bool { return c.Model != nil || c.Application != nil }
func (c Config) RequestBudget() int {
	if c.MaxRequests == 0 {
		return 128
	}
	return c.MaxRequests
}
func (c Config) Lifetime() int {
	if c.TTLSeconds == 0 {
		return 3600
	}
	return c.TTLSeconds
}
func (c Config) Validate() error {
	if c.Lifetime() < 1 || c.Lifetime() > 3600 || c.RequestBudget() < 1 || c.RequestBudget() > 512 {
		return errors.New("broker lifetime must be 1..3600 seconds and request budget 1..512")
	}
	if len(c.Tools) > 16 {
		return errors.New("broker supports at most 16 explicit read tools")
	}
	if c.Model != nil {
		if err := c.Model.Endpoint.Validate(); err != nil {
			return err
		}
		if !modelPattern.MatchString(c.Model.Name) {
			return errors.New("broker model requires an explicit bounded model ID")
		}
		if c.Model.MaxOutputTokens < 0 || c.Model.MaxOutputTokens > 8192 {
			return errors.New("model max_output_tokens must be 1..8192, or omitted for 4096")
		}
	}
	if c.Application != nil {
		if err := c.Application.Validate(); err != nil {
			return err
		}
		if c.Application.CredentialEnv == "" {
			return errors.New("application broker requires an explicit host credential_env; application identity cannot come from the agent")
		}
		if len(c.Tools) == 0 {
			return errors.New("application broker requires explicitly registered tools")
		}
	} else if len(c.Tools) > 0 {
		return errors.New("tools require a trusted application endpoint")
	}
	seen := map[string]bool{}
	for _, t := range c.Tools {
		if !namePattern.MatchString(t.Name) || seen[t.Name] {
			return errors.New("invalid or duplicate registered tool name")
		}
		seen[t.Name] = true
		if len(t.Parameters) < 1 || len(t.Parameters) > 16 || t.Parameters[t.ResourceArgument] != "string" || len(t.Resources) < 1 || len(t.Resources) > 64 {
			return errors.New("tools require a string resource argument, bounded schema and explicit resource grants")
		}
		for k, v := range t.Parameters {
			if !namePattern.MatchString(k) || (v != "string" && v != "integer" && v != "boolean") {
				return errors.New("unsupported tool schema: only required scalar properties are supported")
			}
		}
		resources := map[string]bool{}
		for _, r := range t.Resources {
			if !namePattern.MatchString(r) || resources[r] {
				return errors.New("invalid or duplicate tool resource grant")
			}
			resources[r] = true
		}
	}
	return nil
}
func (e Endpoint) Validate() error {
	u, err := url.Parse(e.URL)
	if len(e.URL) > 2048 {
		return errors.New("broker URL exceeds limit")
	}
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(u.Host, "\\%\r\n") {
		return errors.New("broker endpoint must be an explicit HTTPS origin without credentials, paths, query or fragments")
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return errors.New("broker port must be 1..65535")
		}
	}
	if e.CertificateSHA256 != "" && !digestPattern.MatchString(e.CertificateSHA256) {
		return errors.New("broker certificate_sha256 requires a lowercase SHA-256 fingerprint")
	}
	if e.CredentialEnv != "" && !envPattern.MatchString(e.CredentialEnv) {
		return fmt.Errorf("broker credential_env must name one explicit uppercase host variable")
	}
	return nil
}

// Snapshot keeps a caller's later mutation from broadening a live capability.
func (c Config) Snapshot() Config {
	if c.Model != nil {
		v := *c.Model
		c.Model = &v
	}
	if c.Application != nil {
		v := *c.Application
		c.Application = &v
	}
	tools := make([]Tool, len(c.Tools))
	for i, t := range c.Tools {
		tools[i] = t
		tools[i].Resources = append([]string(nil), t.Resources...)
		tools[i].Parameters = map[string]string{}
		for k, v := range t.Parameters {
			tools[i].Parameters[k] = v
		}
	}
	c.Tools = tools
	return c
}
