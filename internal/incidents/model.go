// Package incidents deterministically reconstructs concise security incidents
// from persisted Ghost evidence. It is a read-only interpretation layer and
// is not part of runtime enforcement or causal inference.
package incidents

import (
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/provenance"
)

const SchemaVersion = 2

type Type string

const (
	DecoyAccess                    Type = "DECOY_ACCESS"
	DecoyAccessWithNetworkActivity Type = "DECOY_ACCESS_WITH_NETWORK_ACTIVITY"
	NetworkPolicyViolation         Type = "NETWORK_POLICY_VIOLATION"
	ContainmentActivated           Type = "CONTAINMENT_ACTIVATED"
	SuspiciousInstructions         Type = "SUSPICIOUS_INSTRUCTIONS"
)

type Severity string

const (
	Low      Severity = "LOW"
	Medium   Severity = "MEDIUM"
	High     Severity = "HIGH"
	Critical Severity = "CRITICAL"
)

type StepType string

const (
	ShadowExposed           StepType = "SHADOW_EXPOSED"
	DecoyAccessed           StepType = "DECOY_ACCESSED"
	ContainmentApplied      StepType = "CONTAINMENT_ACTIVATED"
	NetworkDenied           StepType = "NETWORK_DENIED"
	SuspiciousObserved      StepType = "SUSPICIOUS_INSTRUCTIONS_OBSERVED"
	UntrustedObserved       StepType = "UNTRUSTED_CONTENT_OBSERVED"
	UntrustedExposure       StepType = "UNTRUSTED_CONTENT_EXPOSURE"
	SensitiveRequested      StepType = "SENSITIVE_RESOURCE_REQUESTED"
	LaterSecurityEvent      StepType = "LATER_SECURITY_ACTIVITY"
	ApprovalRequested       StepType = "APPROVAL_REQUIRED"
	ApprovalGrantedStep     StepType = "APPROVAL_GRANTED"
	ApprovalDeniedStep      StepType = "APPROVAL_DENIED"
	ApprovalUnavailableStep StepType = "APPROVAL_UNAVAILABLE"
	ApprovalExpiredStep     StepType = "APPROVAL_EXPIRED"
)

type Report struct {
	Version   int                       `json:"version"`
	Session   provenance.SessionSummary `json:"session"`
	Incidents []Incident                `json:"incidents"`
}

type Incident struct {
	ID                string             `json:"id"`
	SessionID         string             `json:"session_id"`
	Type              Type               `json:"type"`
	Severity          Severity           `json:"severity"`
	SeverityEvidence  []int64            `json:"severity_evidence_event_ids"`
	StartedAt         time.Time          `json:"started_at"`
	EndedAt           time.Time          `json:"ended_at"`
	Summary           string             `json:"summary"`
	Timeline          []Statement        `json:"timeline"`
	EvidenceEventIDs  []int64            `json:"evidence_event_ids"`
	RelevantNodes     []string           `json:"relevant_nodes"`
	RelevantEdges     []string           `json:"relevant_edges"`
	ContainmentAction *ContainmentAction `json:"containment_action,omitempty"`
}

type Statement struct {
	Type             StepType                 `json:"type"`
	Timestamp        time.Time                `json:"timestamp"`
	Text             string                   `json:"text"`
	Level            provenance.EvidenceLevel `json:"level"`
	EvidenceEventIDs []int64                  `json:"evidence_event_ids"`
}

type ContainmentAction struct {
	Action           string    `json:"action"`
	ActivatedAt      time.Time `json:"activated_at"`
	EvidenceEventIDs []int64   `json:"evidence_event_ids"`
}
