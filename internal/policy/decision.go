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
	switch homeMode {
	case HomeDeny:
		return Deny, nil
	case HomeShadow:
		if deceptionEnabled && resourceEnabled {
			return Shadow, nil
		}
		return Deny, nil
	default:
		return "", fmt.Errorf("unsupported home policy %q", homeMode)
	}
}
