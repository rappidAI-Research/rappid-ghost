package events

import (
	"errors"
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
	PolicyAsk            Type = "POLICY_ASK"
	SecurityIncident     Type = "SECURITY_INCIDENT"
	NetworkRequest       Type = "NETWORK_REQUEST"
	NetworkAllow         Type = "NETWORK_ALLOW"
	NetworkDeny          Type = "NETWORK_DENY"
	ContainmentActivated Type = "CONTAINMENT_ACTIVATED"
	ApprovalRequired     Type = "APPROVAL_REQUIRED"
	ApprovalGranted      Type = "APPROVAL_GRANTED"
	ApprovalDenied       Type = "APPROVAL_DENIED"
	ApprovalUnavailable  Type = "APPROVAL_UNAVAILABLE"
	ApprovalExpired      Type = "APPROVAL_EXPIRED"

	// Structured signal types share the persisted event pipeline. Startup trust
	// observation and prompt findings are active; SensitiveResourceRequest is
	// derived only from matching Shadow-access evidence. The rest are reserved.
	UntrustedContentObserved Type = "UNTRUSTED_CONTENT_OBSERVED"
	PromptInjectionSuspected Type = "PROMPT_INJECTION_SUSPECTED"
	SensitiveResourceRequest Type = "SENSITIVE_RESOURCE_REQUESTED"
	PolicyViolation          Type = "POLICY_VIOLATION"
	ResourceLimitTriggered   Type = "RESOURCE_LIMIT_TRIGGERED"
)

type Category string

const (
	Lifecycle       Category = "LIFECYCLE"
	Observation     Category = "OBSERVATION"
	PolicyDecision  Category = "POLICY_DECISION"
	StateTransition Category = "STATE_TRANSITION"
	Incident        Category = "INCIDENT"
)

func (t Type) Category() Category {
	switch t {
	case SessionStart, SessionEnd, ProcessStart, ProcessExit:
		return Lifecycle
	case PolicyAllow, PolicyDeny, PolicyShadow, PolicyAsk, ApprovalRequired, ApprovalGranted, ApprovalDenied, ApprovalUnavailable, ApprovalExpired:
		return PolicyDecision
	case ContainmentActivated:
		return StateTransition
	case SecurityIncident, PolicyViolation, ResourceLimitTriggered:
		return Incident
	default:
		return Observation
	}
}

func (t Type) GenericSecuritySignal() bool {
	switch t {
	case UntrustedContentObserved, PromptInjectionSuspected, SensitiveResourceRequest, PolicyViolation, ResourceLimitTriggered:
		return true
	default:
		return false
	}
}

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

func (e Event) Validate() error {
	if e.SessionID == "" || e.Timestamp.IsZero() || e.Type == "" {
		return errors.New("event requires session ID, timestamp, and type")
	}
	if e.Decision != nil && !e.Decision.Valid() {
		return errors.New("event contains invalid policy decision")
	}
	return nil
}
