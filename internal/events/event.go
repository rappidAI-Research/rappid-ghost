package events

import (
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/policy"
)

type Type string

const (
	SessionStart         Type = "SESSION_START"
	SessionEnd           Type = "SESSION_END"
	ProcessStart         Type = "PROCESS_START"
	ProcessExit          Type = "PROCESS_EXIT"
	DecoyCreated         Type = "DECOY_CREATED"
	DecoyAccess          Type = "DECOY_ACCESS"
	PolicyAllow          Type = "POLICY_ALLOW"
	PolicyDeny           Type = "POLICY_DENY"
	PolicyShadow         Type = "POLICY_SHADOW"
	SecurityIncident     Type = "SECURITY_INCIDENT"
	NetworkRequest       Type = "NETWORK_REQUEST"
	NetworkAllow         Type = "NETWORK_ALLOW"
	NetworkDeny          Type = "NETWORK_DENY"
	ContainmentActivated Type = "CONTAINMENT_ACTIVATED"
)

// Event is a JSON-compatible record of observable Ghost activity. Fields are
// optional where an event type does not naturally supply them.
type Event struct {
	ID        int64            `json:"id"`
	SessionID string           `json:"session_id"`
	Timestamp time.Time        `json:"timestamp"`
	Type      Type             `json:"type"`
	Subject   string           `json:"subject,omitempty"`
	Resource  string           `json:"resource,omitempty"`
	Action    string           `json:"action,omitempty"`
	Decision  *policy.Decision `json:"decision,omitempty"`
	Metadata  map[string]any   `json:"metadata,omitempty"`
}
