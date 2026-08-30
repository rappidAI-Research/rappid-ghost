package network

import "testing"

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
