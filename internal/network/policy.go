package network

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/rappidAI-research/rappid-ghost/internal/policy"
)

type Mode string

const (
	Deny      Mode = "deny"
	Allowlist Mode = "allowlist"
)

type Policy struct {
	Mode  Mode
	Allow []string
}

func NewPolicy(mode string, allow []string) (Policy, error) {
	// "none" was an earlier spelling for a disabled network. Keep it as
	// a fail-closed compatibility alias, but never expose it as a runtime mode.
	if mode == "none" {
		mode = string(Deny)
	}
	policy := Policy{Mode: Mode(mode)}
	if policy.Mode != Deny && policy.Mode != Allowlist {
		return Policy{}, errors.New("network mode must be deny or allowlist")
	}
	seen := make(map[string]bool, len(allow))
	for _, value := range allow {
		host, err := NormalizeHostname(value)
		if err != nil {
			return Policy{}, fmt.Errorf("invalid allowlist hostname %q: %w", value, err)
		}
		if seen[host] {
			return Policy{}, fmt.Errorf("duplicate allowlist hostname %q", host)
		}
		seen[host] = true
		policy.Allow = append(policy.Allow, host)
	}
	if policy.Mode == Deny && len(policy.Allow) != 0 {
		return Policy{}, errors.New("network allowlist must be empty when mode is deny")
	}
	if policy.Mode == Allowlist && len(policy.Allow) == 0 {
		return Policy{}, errors.New("network allowlist must contain at least one hostname")
	}
	return policy, nil
}

func (p Policy) Allows(host string, port int) bool {
	decision, err := p.Decision(host, port, policy.StateNormal)
	return err == nil && decision == policy.Allow
}

// Decision is the network policy integration point for authoritative session
// state. Unknown state fails closed; containment always overrides an allowlist.
func (p Policy) Decision(host string, port int, state policy.SecurityState) (policy.Decision, error) {
	if !state.Valid() {
		return policy.Deny, fmt.Errorf("invalid session security state %q", state)
	}
	base := policy.Deny
	if p.Mode != Allowlist || (port != 80 && port != 443) {
		return policy.Evaluate(base, policy.EvaluationContext{Resource: policy.ResourceNetwork, State: state})
	}
	normalized, err := NormalizeHostname(host)
	if err != nil {
		return policy.Evaluate(base, policy.EvaluationContext{Resource: policy.ResourceNetwork, State: state})
	}
	for _, allowed := range p.Allow {
		if normalized == allowed {
			base = policy.Allow
			break
		}
	}
	return policy.Evaluate(base, policy.EvaluationContext{Resource: policy.ResourceNetwork, State: state})
}

// NormalizeHostname implements exact ASCII hostname matching. A final DNS root
// dot and case are normalized; local-use names, wildcards, ports, URL syntax,
// and raw IPs are rejected. IDNs must use their explicit ASCII punycode form.
func NormalizeHostname(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	if value == "" || len(value) > 253 {
		return "", errors.New("hostname is empty or too long")
	}
	if strings.ContainsAny(value, ":/[]@*?#%") || net.ParseIP(value) != nil {
		return "", errors.New("ports, URLs, wildcards, and IP addresses are not supported")
	}
	onlyDigitsAndDots := true
	for _, character := range value {
		if (character < '0' || character > '9') && character != '.' {
			onlyDigitsAndDots = false
			break
		}
	}
	if onlyDigitsAndDots {
		return "", errors.New("numeric IP-like destinations are not supported")
	}
	if isLocalHostname(value) {
		return "", errors.New("local and single-label hostnames are not supported")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("hostname contains an invalid label")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", errors.New("hostname must contain only ASCII letters, digits, hyphens, and dots")
			}
		}
	}
	return value, nil
}

func isLocalHostname(value string) bool {
	if !strings.Contains(value, ".") {
		return true
	}
	for _, suffix := range []string{".localhost", ".local", ".localdomain", ".internal", ".lan", ".home.arpa"} {
		if strings.HasSuffix(value, suffix) {
			return true
		}
	}
	return false
}
