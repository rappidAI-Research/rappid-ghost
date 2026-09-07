// Package trust defines Ghost's small deterministic trust vocabulary and the
// monotonic exposure context used during one session. It does not infer model
// intent or implement byte-level information-flow tracking.
package trust

import "fmt"

type Class string

const (
	Trusted   Class = "TRUSTED"
	Untrusted Class = "UNTRUSTED"
	Sensitive Class = "SENSITIVE"
	Shadow    Class = "SHADOW"
)

func (c Class) Valid() bool {
	switch c {
	case Trusted, Untrusted, Sensitive, Shadow:
		return true
	default:
		return false
	}
}

// Severity is the highest deterministic prompt-guard severity observed in a
// session. Empty means that no prompt finding has been observed.
type Severity string

const (
	Low      Severity = "LOW"
	Medium   Severity = "MEDIUM"
	High     Severity = "HIGH"
	Critical Severity = "CRITICAL"
)

func (s Severity) ValidOrEmpty() bool {
	switch s {
	case "", Low, Medium, High, Critical:
		return true
	default:
		return false
	}
}

func (s Severity) rank() int {
	switch s {
	case Low:
		return 1
	case Medium:
		return 2
	case High:
		return 3
	case Critical:
		return 4
	default:
		return 0
	}
}

// Context contains only session-local facts that can tighten future policy or
// enrich evidence. Its transitions are monotonic for the lifetime of a run.
type Context struct {
	UntrustedInputObserved bool
	PromptSeverity         Severity
	ShadowResourceAccessed bool
}

func (c Context) Validate() error {
	if !c.PromptSeverity.ValidOrEmpty() {
		return fmt.Errorf("invalid prompt severity %q", c.PromptSeverity)
	}
	if c.PromptSeverity != "" && !c.UntrustedInputObserved {
		return fmt.Errorf("prompt finding requires untrusted-input observation")
	}
	return nil
}

func (c Context) ObserveUntrustedInput() Context {
	c.UntrustedInputObserved = true
	return c
}

func (c Context) ObservePromptFinding(severity Severity) (Context, error) {
	if severity == "" || !severity.ValidOrEmpty() {
		return c, fmt.Errorf("invalid prompt severity %q", severity)
	}
	c.UntrustedInputObserved = true
	if severity.rank() > c.PromptSeverity.rank() {
		c.PromptSeverity = severity
	}
	return c, nil
}

func (c Context) ObserveShadowAccess() Context {
	c.ShadowResourceAccessed = true
	return c
}
