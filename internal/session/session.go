package session

import (
	"crypto/rand"
	"fmt"
	"time"

	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
)

type Status string

const (
	Created   Status = "created"
	Running   Status = "running"
	Completed Status = "completed"
	Failed    Status = "failed"
)

func (s Status) Valid() bool {
	switch s {
	case Created, Running, Completed, Failed:
		return true
	default:
		return false
	}
}

type Session struct {
	ID          string            `json:"id"`
	CreatedAt   time.Time         `json:"created_at"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
	Command     []string          `json:"command"`
	Runtime     string            `json:"runtime"`
	Status      Status            `json:"status"`
	ExitCode    *int              `json:"exit_code,omitempty"`
	NetworkMode ghostnetwork.Mode `json:"network_mode"`
	Contained   bool              `json:"contained"`
}

func NewID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate session ID: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
