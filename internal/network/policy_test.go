package network

import (
	"testing"

	ghostpolicy "github.com/rappidAI-research/rappid-ghost/internal/policy"
)

func TestPolicyUsesExactNormalizedHostnameMatching(t *testing.T) {
	policy, err := NewPolicy("allowlist", []string{"GitHub.COM.", "api.github.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		host string
		port int
		want bool
	}{
		{"github.com", 443, true},
		{"GITHUB.COM.", 80, true},
		{"api.github.com", 443, true},
		{"raw.github.com", 443, false},
		{"evilgithub.com", 443, false},
		{"github.com", 22, false},
		{"140.82.121.3", 443, false},
		{"::1", 443, false},
	} {
		if got := policy.Allows(test.host, test.port); got != test.want {
			t.Errorf("Allows(%q, %d) = %v, want %v", test.host, test.port, got, test.want)
		}
	}
}

func TestContainedSessionOverridesAllowlist(t *testing.T) {
	value, err := NewPolicy("allowlist", []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := value.Decision("example.com", 443, ghostpolicy.StateContained)
	if err != nil || decision != ghostpolicy.Deny {
		t.Fatalf("contained decision = %q, %v; want DENY", decision, err)
	}
	decision, err = value.Decision("example.com", 443, ghostpolicy.StateNormal)
	if err != nil || decision != ghostpolicy.Allow {
		t.Fatalf("normal decision = %q, %v; want ALLOW", decision, err)
	}
	if decision, err = value.Decision("example.com", 443, "UNKNOWN"); err == nil || decision != ghostpolicy.Deny {
		t.Fatalf("unknown-state decision = %q, %v; want fail-closed DENY", decision, err)
	}
}

func TestApprovalDestinationsAreExactAndContainmentOverridesAsk(t *testing.T) {
	value, err := NewPolicyWithApproval("allowlist", []string{"allowed.example.com"}, []string{"ask.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		host  string
		port  int
		state ghostpolicy.SecurityState
		want  ghostpolicy.Decision
	}{
		{"allowed.example.com", 443, ghostpolicy.StateNormal, ghostpolicy.Allow},
		{"ask.example.com", 443, ghostpolicy.StateNormal, ghostpolicy.Ask},
		{"sub.ask.example.com", 443, ghostpolicy.StateNormal, ghostpolicy.Deny},
		{"ask.example.com", 22, ghostpolicy.StateNormal, ghostpolicy.Deny},
		{"ask.example.com", 443, ghostpolicy.StateContained, ghostpolicy.Deny},
	} {
		got, decisionErr := value.Decision(test.host, test.port, test.state)
		if decisionErr != nil || got != test.want {
			t.Errorf("Decision(%q, %d, %s) = %s, %v; want %s", test.host, test.port, test.state, got, decisionErr, test.want)
		}
	}
	if _, err := NewPolicyWithApproval("allowlist", []string{"same.example.com"}, []string{"SAME.EXAMPLE.COM."}); err == nil {
		t.Fatal("overlapping ALLOW and ASK hostname was accepted")
	}
	for _, unsafe := range []string{"127.0.0.1", "localhost", "host.docker.internal", "169.254.169.254", "*.example.com"} {
		if _, err := NewPolicyWithApproval("allowlist", nil, []string{unsafe}); err == nil {
			t.Errorf("unsafe ASK hostname %q was accepted", unsafe)
		}
	}
}

func TestPolicyValidationFailsClosed(t *testing.T) {
	for _, test := range []struct {
		mode  string
		allow []string
	}{
		{"", nil},
		{"host", nil},
		{"allowlist", nil},
		{"deny", []string{"example.com"}},
		{"allowlist", []string{"*.example.com"}},
		{"allowlist", []string{"127.0.0.1"}},
		{"allowlist", []string{"0177.0.0.1"}},
		{"allowlist", []string{"2130706433"}},
		{"allowlist", []string{"[::1]"}},
		{"allowlist", []string{"localhost"}},
		{"allowlist", []string{"service.localhost"}},
		{"allowlist", []string{"host.docker.internal"}},
		{"allowlist", []string{"gateway.docker.internal"}},
		{"allowlist", []string{"metadata.google.internal"}},
		{"allowlist", []string{"single-label"}},
		{"allowlist", []string{"example.com:443"}},
		{"allowlist", []string{"example.com", "EXAMPLE.COM."}},
	} {
		if _, err := NewPolicy(test.mode, test.allow); err == nil {
			t.Errorf("NewPolicy(%q, %#v) unexpectedly succeeded", test.mode, test.allow)
		}
	}
	policy, err := NewPolicy("none", nil)
	if err != nil || policy.Mode != Deny {
		t.Fatalf("legacy none policy = %#v, %v", policy, err)
	}
}
