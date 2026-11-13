package config

import "fmt"

// Profiles constrain explicit policy. They never fill in broader permissions
// or silently rewrite configuration based on untrusted project markers.
func (c Config) validateProfile() error {
	switch c.Profile {
	case "":
		return nil // Backward-compatible explicit policy, no named profile.
	case "coding":
		if c.Policy.Home == "shadow" && c.Deception.Enabled && c.OnDecoyAccess.Network != "deny" {
			return fmt.Errorf("profile coding requires on_decoy_access.network: deny when SHADOW is enabled")
		}
	case "document-processing", "restricted":
		if c.Workspace.Mode != "read-only" || (c.Network.Mode != "deny" && c.Network.Mode != "none") || len(c.Network.Allow)+len(c.Network.Ask) != 0 || c.Policy.Home != "deny" {
			return fmt.Errorf("profile %s requires workspace.mode: read-only, network.mode: deny with empty allow/ask, and policy.home: deny", c.Profile)
		}
		if c.Profile == "restricted" && (c.Runtime.Limits.MemoryMiB > 2048 || c.Runtime.Limits.CPUMillis > 1000 || c.Runtime.Limits.PIDs > 256 || c.Runtime.Limits.TimeoutSeconds > 3600 || c.Runtime.Limits.TmpMiB > 64) {
			return fmt.Errorf("profile restricted requires limits no greater than Ghost defaults")
		}
	default:
		return fmt.Errorf("unknown profile %q; choose coding, document-processing or restricted", c.Profile)
	}
	return nil
}
