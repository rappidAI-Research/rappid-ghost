package policy

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
