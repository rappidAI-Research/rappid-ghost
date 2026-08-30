package session

import (
	"context"
	"fmt"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/events"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
)

type EventStore interface {
	CreateSession(ctx context.Context, value Session) error
	UpdateSession(ctx context.Context, value Session) error
	AddEvent(ctx context.Context, event *events.Event) error
}

type Manager struct {
	store  EventStore
	runner ghruntime.Runtime
	now    func() time.Time
}

func NewManager(store EventStore, runner ghruntime.Runtime) *Manager {
	return &Manager{store: store, runner: runner, now: func() time.Time { return time.Now().UTC() }}
}

func (m *Manager) Run(ctx context.Context, request ghruntime.RunRequest) (Session, error) {
	if len(request.Command) == 0 {
		return Session{}, fmt.Errorf("no command provided")
	}
	id, err := NewID()
	if err != nil {
		return Session{}, err
	}
	value := Session{
		ID:        id,
		CreatedAt: m.now(),
		Command:   append([]string(nil), request.Command...),
		Runtime:   m.runner.Name(),
		Status:    Created,
	}
	if err := m.store.CreateSession(ctx, value); err != nil {
		return Session{}, err
	}
	if err := m.addEvent(ctx, value.ID, events.SessionStart, "ghost", "", "start", nil); err != nil {
		return value, err
	}
	value.Status = Running
	if err := m.store.UpdateSession(ctx, value); err != nil {
		return value, err
	}
	if err := m.addEvent(ctx, value.ID, events.ProcessStart, request.Command[0], "/workspace", "execute", map[string]any{
		"argv":                request.Command,
		"workspace_read_only": request.WorkspaceReadOnly,
		"network":             "none",
	}); err != nil {
		return value, err
	}

	result, runErr := m.runner.Run(ctx, request)
	if result.Started {
		exitCode := result.ExitCode
		value.ExitCode = &exitCode
		metadata := map[string]any{"exit_code": exitCode}
		if runErr != nil {
			metadata["runtime_error"] = runErr.Error()
		}
		if err := m.addEvent(ctx, value.ID, events.ProcessExit, request.Command[0], "/workspace", "exit", metadata); err != nil {
			return value, err
		}
	}

	completedAt := m.now()
	value.CompletedAt = &completedAt
	if runErr != nil || value.ExitCode == nil || *value.ExitCode != 0 {
		value.Status = Failed
	} else {
		value.Status = Completed
	}
	if err := m.store.UpdateSession(ctx, value); err != nil {
		return value, err
	}
	metadata := map[string]any{"status": value.Status}
	if value.ExitCode != nil {
		metadata["exit_code"] = *value.ExitCode
	}
	if runErr != nil {
		metadata["error"] = runErr.Error()
	}
	if err := m.addEvent(ctx, value.ID, events.SessionEnd, "ghost", "", string(value.Status), metadata); err != nil {
		return value, err
	}
	return value, runErr
}

func (m *Manager) addEvent(ctx context.Context, sessionID string, eventType events.Type, subject, resource, action string, metadata map[string]any) error {
	event := &events.Event{
		SessionID: sessionID,
		Timestamp: m.now(),
		Type:      eventType,
		Subject:   subject,
		Resource:  resource,
		Action:    action,
		Metadata:  metadata,
	}
	return m.store.AddEvent(ctx, event)
}
