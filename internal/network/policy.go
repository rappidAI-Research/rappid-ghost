package network

import (
	"errors"
	"fmt"
	"net"
	"strings"
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
	if p.Mode != Allowlist || (port != 80 && port != 443) {
		return false
	}
	normalized, err := NormalizeHostname(host)
	if err != nil {
		return false
	}
	for _, allowed := range p.Allow {
		if normalized == allowed {
			return true
		}
	}
	return false
}

// NormalizeHostname implements exact ASCII hostname matching. A final DNS root
// dot and case are normalized; wildcards, ports, URL syntax, and raw IPs are
// rejected. IDNs must be configured in their explicit ASCII punycode form.
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
