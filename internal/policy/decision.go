package policy

import "fmt"

// Decision is the deterministic outcome of a Ghost policy evaluation.
type Decision string

const (
	Allow  Decision = "ALLOW"
	Deny   Decision = "DENY"
	Shadow Decision = "SHADOW"
)

func (d Decision) Valid() bool {
	switch d {
	case Allow, Deny, Shadow:
		return true
	default:
		return false
	}
}

const (
	HomeDeny   = "deny"
	HomeShadow = "shadow"
)

// HomeResourceDecision evaluates the deliberately narrow Shadow Home policy.
// Disabling deception fails closed; it never turns a protected resource into
// an ALLOW decision.
func HomeResourceDecision(homeMode string, deceptionEnabled, resourceEnabled bool) (Decision, error) {
	var base Decision
	switch homeMode {
	case HomeDeny:
		base = Deny
	case HomeShadow:
		if deceptionEnabled && resourceEnabled {
			base = Shadow
		} else {
			base = Deny
		}
	default:
		return "", fmt.Errorf("unsupported home policy %q", homeMode)
	}
	return Evaluate(base, EvaluationContext{Resource: ResourceHome, State: StateNormal})
}
