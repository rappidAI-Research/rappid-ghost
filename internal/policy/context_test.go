package policy

import (
	"testing"

	"github.com/rappidAI-research/rappid-ghost/internal/trust"
)

func TestTransitionIsMonotonic(t *testing.T) {
	if got, err := Transition(StateNormal, StateContained); err != nil || got != StateContained {
		t.Fatalf("Transition(NORMAL, CONTAINED) = %q, %v", got, err)
	}
	if got, err := Transition(StateContained, StateContained); err != nil || got != StateContained {
		t.Fatalf("Transition(CONTAINED, CONTAINED) = %q, %v", got, err)
	}
	if _, err := Transition(StateContained, StateNormal); err == nil {
		t.Fatal("Transition(CONTAINED, NORMAL) succeeded")
	}
}

func TestEvaluateContainedNetworkFailsClosed(t *testing.T) {
	got, err := Evaluate(Allow, EvaluationContext{Resource: ResourceNetwork, State: StateContained})
	if err != nil || got != Deny {
		t.Fatalf("Evaluate() = %q, %v; want DENY", got, err)
	}
	if _, err := Evaluate(Allow, EvaluationContext{Resource: ResourceNetwork, State: "UNKNOWN"}); err == nil {
		t.Fatal("Evaluate() accepted unknown security state")
	}
}

func TestPromptSignalCannotMakePolicyMorePermissive(t *testing.T) {
	context := EvaluationContext{
		Resource: ResourceHome, ResourceTrust: trust.Shadow, State: StateNormal,
		Trust:   trust.Context{UntrustedInputObserved: true, PromptSeverity: trust.High},
		Signals: []SignalKind{SignalUntrustedContentObserved, SignalPromptInjectionSuspected},
	}
	if !context.HasSignal(SignalPromptInjectionSuspected) {
		t.Fatal("prompt signal missing from policy context")
	}
	for _, base := range []Decision{Allow, Deny, Shadow} {
		got, err := Evaluate(base, context)
		if err != nil || got != base {
			t.Fatalf("Evaluate(%s) = %s, %v", base, got, err)
		}
	}
	context.Signals = []SignalKind{"UNKNOWN"}
	if _, err := Evaluate(Allow, context); err == nil {
		t.Fatal("unknown security signal accepted")
	}
}

func TestTrustContextCannotMakePolicyMorePermissive(t *testing.T) {
	context := EvaluationContext{
		Resource: ResourceNetwork, ResourceTrust: trust.Untrusted, State: StateNormal,
		Trust:   trust.Context{UntrustedInputObserved: true, PromptSeverity: trust.Critical, ShadowResourceAccessed: true},
		Signals: []SignalKind{SignalUntrustedContentObserved, SignalPromptInjectionSuspected, SignalShadowResourceAccessed},
	}
	for _, base := range []Decision{Allow, Deny} {
		got, err := Evaluate(base, context)
		if err != nil || got != base {
			t.Fatalf("Evaluate(%s) = %s, %v", base, got, err)
		}
	}
	context.ResourceTrust = "UNKNOWN"
	if _, err := Evaluate(Allow, context); err == nil {
		t.Fatal("unknown trust class accepted")
	}
	context.ResourceTrust = trust.Untrusted
	context.Trust = trust.Context{PromptSeverity: trust.High}
	if _, err := Evaluate(Allow, context); err == nil {
		t.Fatal("contradictory trust context accepted")
	}
}
