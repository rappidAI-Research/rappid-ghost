// Package provenance reconstructs explainable session relationships from
// persisted Ghost evidence. It is observational and is not an enforcement or
// causal-inference component.
package provenance

import (
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/events"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
)

const SchemaVersion = 1

type NodeType string

const (
	SessionNode            NodeType = "SESSION"
	ProcessNode            NodeType = "PROCESS"
	ResourceNode           NodeType = "RESOURCE"
	DecoyNode              NodeType = "DECOY"
	NetworkDestinationNode NodeType = "NETWORK_DESTINATION"
	PolicyDecisionNode     NodeType = "POLICY_DECISION"
	IncidentNode           NodeType = "INCIDENT"
)

type EdgeType string

const (
	Started    EdgeType = "STARTED"
	Read       EdgeType = "READ"
	Accessed   EdgeType = "ACCESSED"
	Requested  EdgeType = "REQUESTED"
	Allowed    EdgeType = "ALLOWED"
	Denied     EdgeType = "DENIED"
	Shadowed   EdgeType = "SHADOWED"
	Triggered  EdgeType = "TRIGGERED"
	Contained  EdgeType = "CONTAINED"
	FollowedBy EdgeType = "FOLLOWED_BY"
)

type EvidenceLevel string

const (
	Observed EvidenceLevel = "OBSERVED"
	Derived  EvidenceLevel = "DERIVED"
)

type Graph struct {
	Version  int            `json:"version"`
	Session  SessionSummary `json:"session"`
	Nodes    []Node         `json:"nodes"`
	Edges    []Edge         `json:"edges"`
	Evidence []Evidence     `json:"evidence"`
}

type SessionSummary struct {
	ID        string         `json:"id"`
	Status    session.Status `json:"status"`
	Runtime   string         `json:"runtime"`
	Contained bool           `json:"contained"`
}

type Node struct {
	ID       string   `json:"id"`
	Type     NodeType `json:"type"`
	Label    string   `json:"label"`
	Evidence []int64  `json:"evidence,omitempty"`
}

type Edge struct {
	ID       string        `json:"id"`
	Type     EdgeType      `json:"type"`
	From     string        `json:"from"`
	To       string        `json:"to"`
	Level    EvidenceLevel `json:"level"`
	Evidence []int64       `json:"evidence,omitempty"`
}

type Evidence struct {
	EventID   int64       `json:"event_id"`
	Timestamp time.Time   `json:"timestamp"`
	Type      events.Type `json:"type"`
}
