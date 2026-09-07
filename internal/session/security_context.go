package session

import (
	"fmt"

	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	"github.com/rappidAI-research/rappid-ghost/internal/trust"
)

// runSecurityContext is session-local, monotonic context reconstructed from
// evidence as the manager records it. Persisted events remain the durable
// source of truth; this value is only the policy handoff for the active run.
type runSecurityContext struct {
	trust   trust.Context
	signals []policy.SignalKind
}

func (c *runSecurityContext) observeUntrustedInput() {
	c.trust = c.trust.ObserveUntrustedInput()
	c.addSignal(policy.SignalUntrustedContentObserved)
}

func (c *runSecurityContext) observePromptFinding(severity trust.Severity) error {
	next, err := c.trust.ObservePromptFinding(severity)
	if err != nil {
		return err
	}
	c.trust = next
	c.addSignal(policy.SignalPromptInjectionSuspected)
	return nil
}

func (c *runSecurityContext) observeShadowAccess() {
	c.trust = c.trust.ObserveShadowAccess()
	c.addSignal(policy.SignalShadowResourceAccessed)
	c.addSignal(policy.SignalSensitiveResourceRequested)
}

func (c *runSecurityContext) addSignal(candidate policy.SignalKind) {
	for _, signal := range c.signals {
		if signal == candidate {
			return
		}
	}
	c.signals = append(c.signals, candidate)
}

func (c runSecurityContext) evaluation(resource policy.ResourceKind, resourceTrust trust.Class, state policy.SecurityState) policy.EvaluationContext {
	return policy.EvaluationContext{
		Resource: resource, ResourceTrust: resourceTrust, State: state,
		Trust: c.trust, Signals: append([]policy.SignalKind(nil), c.signals...),
	}
}

func promptTrustSeverity(value string) (trust.Severity, error) {
	severity := trust.Severity(value)
	if severity == "" || !severity.ValidOrEmpty() {
		return "", fmt.Errorf("invalid prompt finding severity %q", value)
	}
	return severity, nil
}
