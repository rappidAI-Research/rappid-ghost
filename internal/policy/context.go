package policy

import (
	"fmt"

	"github.com/rappidAI-research/rappid-ghost/internal/trust"
)

// SecurityState is the authoritative logical security state of one session.
// Containment is monotonic: a contained session cannot return to normal.
type SecurityState string

const (
	StateNormal    SecurityState = "NORMAL"
	StateContained SecurityState = "CONTAINED"
)

func (s SecurityState) Valid() bool {
	return s == StateNormal || s == StateContained
}

func (s SecurityState) IsContained() bool {
	return s == StateContained
}

// Transition applies the deliberately small, monotonic session-state model.
func Transition(current, next SecurityState) (SecurityState, error) {
	if !current.Valid() || !next.Valid() {
		return "", fmt.Errorf("invalid security state transition %q -> %q", current, next)
	}
	if current == StateContained && next == StateNormal {
		return "", fmt.Errorf("contained session cannot return to normal")
	}
	return next, nil
}

type ResourceKind string

const (
	ResourceWorkspace ResourceKind = "workspace"
	ResourceHome      ResourceKind = "home"
	ResourceNetwork   ResourceKind = "network"
)

type EvaluationContext struct {
	Resource      ResourceKind
	ResourceTrust trust.Class
	State         SecurityState
	Trust         trust.Context
	Signals       []SignalKind
}

// SignalKind is a deterministic fact available to policy evaluation. Signals
// can only preserve or tighten a base decision; they are never proof that an
// operation is safe.
type SignalKind string

const (
	SignalUntrustedContentObserved   SignalKind = "UNTRUSTED_CONTENT_OBSERVED"
	SignalPromptInjectionSuspected   SignalKind = "PROMPT_INJECTION_SUSPECTED"
	SignalSensitiveResourceRequested SignalKind = "SENSITIVE_RESOURCE_REQUESTED"
	SignalShadowResourceAccessed     SignalKind = "SHADOW_RESOURCE_ACCESSED"
)

func (s SignalKind) Valid() bool {
	switch s {
	case SignalUntrustedContentObserved, SignalPromptInjectionSuspected, SignalSensitiveResourceRequested, SignalShadowResourceAccessed:
		return true
	default:
		return false
	}
}

func (c EvaluationContext) HasSignal(candidate SignalKind) bool {
	for _, signal := range c.Signals {
		if signal == candidate {
			return true
		}
	}
	return false
}

// Evaluate applies shared session context to an already deterministic base
// decision. Semantic detectors may eventually provide input to this context,
// but they cannot bypass its fail-closed enforcement rules.
func Evaluate(base Decision, context EvaluationContext) (Decision, error) {
	if !base.Valid() {
		return "", fmt.Errorf("invalid base policy decision %q", base)
	}
	if !context.State.Valid() {
		return "", fmt.Errorf("invalid session security state %q", context.State)
	}
	if context.ResourceTrust != "" && !context.ResourceTrust.Valid() {
		return "", fmt.Errorf("invalid resource trust class %q", context.ResourceTrust)
	}
	if err := context.Trust.Validate(); err != nil {
		return "", fmt.Errorf("invalid session trust context: %w", err)
	}
	for _, signal := range context.Signals {
		if !signal.Valid() {
			return "", fmt.Errorf("invalid policy security signal %q", signal)
		}
	}
	switch context.Resource {
	case ResourceWorkspace, ResourceHome, ResourceNetwork:
	default:
		return "", fmt.Errorf("invalid policy resource %q", context.Resource)
	}
	if context.Resource == ResourceNetwork && context.State == StateContained {
		return Deny, nil
	}
	return base, nil
}
