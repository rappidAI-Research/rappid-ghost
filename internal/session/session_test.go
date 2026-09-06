package session

import (
	"testing"

	"github.com/rappidAI-research/rappid-ghost/internal/policy"
)

func TestSessionSecurityStateCannotDeescalate(t *testing.T) {
	value := Session{SecurityState: policy.StateNormal}
	if err := value.TransitionSecurityState(policy.StateContained); err != nil || !value.IsContained() {
		t.Fatalf("containment transition = %+v, %v", value, err)
	}
	if err := value.TransitionSecurityState(policy.StateNormal); err == nil || !value.IsContained() {
		t.Fatalf("de-escalation changed state: %+v, %v", value, err)
	}
}
