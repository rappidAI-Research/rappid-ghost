package policy

import "testing"

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
