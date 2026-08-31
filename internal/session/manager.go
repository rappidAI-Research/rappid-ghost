package session

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/deception"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
)

type EventStore interface {
	CreateSession(ctx context.Context, value Session) error
	UpdateSession(ctx context.Context, value Session) error
	AddEvent(ctx context.Context, event *events.Event) error
	CreateDecoy(ctx context.Context, decoy deception.Decoy) error
	TriggerDecoy(ctx context.Context, sessionID, id string, triggeredAt time.Time) (bool, error)
}

type ResourcePolicy struct {
	AWSCredentials bool
	SSHPrivateKey  bool
	EnvFile        bool
}

type RunRequest struct {
	Runtime          ghruntime.RunRequest
	SessionsDir      string
	HomePolicy       string
	DeceptionEnabled bool
	Resources        ResourcePolicy
	IncidentSeverity string
	RecordIncident   bool
	NetworkPolicy    ghostnetwork.Policy
	ContainOnDecoy   bool
}

type Manager struct {
	store     EventStore
	runner    ghruntime.Runtime
	generator *deception.Generator
	now       func() time.Time
}

func NewManager(store EventStore, runner ghruntime.Runtime) *Manager {
	return &Manager{
		store: store, runner: runner, generator: deception.NewGenerator(),
		now: func() time.Time { return time.Now().UTC() },
	}
}

func (m *Manager) Run(ctx context.Context, request RunRequest) (Session, error) {
	if len(request.Runtime.Command) == 0 {
		return Session{}, fmt.Errorf("no command provided")
	}
	if request.NetworkPolicy.Mode == "" {
		request.NetworkPolicy.Mode = ghostnetwork.Deny
	}
	validatedNetwork, err := ghostnetwork.NewPolicy(string(request.NetworkPolicy.Mode), request.NetworkPolicy.Allow)
	if err != nil {
		return Session{}, fmt.Errorf("invalid network policy: %w", err)
	}
	request.NetworkPolicy = validatedNetwork
	id, err := NewID()
	if err != nil {
		return Session{}, err
	}
	value := Session{
		ID:          id,
		CreatedAt:   m.now(),
		Command:     append([]string(nil), request.Runtime.Command...),
		Runtime:     m.runner.Name(),
		Status:      Created,
		NetworkMode: request.NetworkPolicy.Mode,
	}
	if err := m.store.CreateSession(ctx, value); err != nil {
		return Session{}, err
	}
	if err := m.addEvent(ctx, value.ID, events.SessionStart, "ghost", "", "start", nil, nil); err != nil {
		return m.fail(ctx, value, err)
	}
	value.Status = Running
	if err := m.store.UpdateSession(ctx, value); err != nil {
		return m.fail(ctx, value, err)
	}

	allow := policy.Allow
	deny := policy.Deny
	if err := m.addEvent(ctx, value.ID, events.PolicyAllow, "workspace", "/workspace", "expose", &allow, nil); err != nil {
		return m.fail(ctx, value, err)
	}
	if value.NetworkMode == ghostnetwork.Allowlist {
		if err := m.addEvent(ctx, value.ID, events.PolicyAllow, "network", "http/https", "restrict to exact allowlist", &allow, map[string]any{
			"mode": value.NetworkMode, "allow": request.NetworkPolicy.Allow,
		}); err != nil {
			return m.fail(ctx, value, err)
		}
	} else {
		if err := m.addEvent(ctx, value.ID, events.PolicyDeny, "network", "network", "disable", &deny, map[string]any{"mode": ghostnetwork.Deny}); err != nil {
			return m.fail(ctx, value, err)
		}
	}

	shadowResources, decisions, err := evaluateHomeResources(request)
	if err != nil {
		return m.fail(ctx, value, err)
	}
	manifest, err := m.generator.Prepare(value.ID, request.SessionsDir, shadowResources)
	if err != nil {
		return m.fail(ctx, value, fmt.Errorf("prepare synthetic home: %w", err))
	}
	request.Runtime.SessionID = value.ID
	request.Runtime.SessionDir = manifest.SessionDir
	request.Runtime.SyntheticHome = manifest.SyntheticHome
	request.Runtime.NetworkPolicy = request.NetworkPolicy
	request.Runtime.ContainOnDecoy = request.ContainOnDecoy
	decoyByID := make(map[string]deception.Decoy, len(manifest.Decoys))
	for _, decoy := range manifest.Decoys {
		decoyByID[decoy.ID] = decoy
		if err := m.store.CreateDecoy(ctx, decoy); err != nil {
			return m.fail(ctx, value, err)
		}
		if err := m.addEvent(ctx, value.ID, events.DecoyCreated, "ghost", decoy.GuestPath, "create", nil, map[string]any{
			"decoy_id": decoy.ID,
			"type":     decoy.Type,
		}); err != nil {
			return m.fail(ctx, value, err)
		}
		shadow := policy.Shadow
		if err := m.addEvent(ctx, value.ID, events.PolicyShadow, "home", decoy.GuestPath, "expose synthetic resource", &shadow, map[string]any{
			"decoy_id": decoy.ID,
			"type":     decoy.Type,
		}); err != nil {
			return m.fail(ctx, value, err)
		}
		request.Runtime.ShadowResources = append(request.Runtime.ShadowResources, ghruntime.ShadowResource{
			DecoyID: decoy.ID, GuestPath: decoy.GuestPath,
		})
	}
	for _, resource := range deception.KnownResources() {
		if decisions[resource.GuestPath] != policy.Deny {
			continue
		}
		if err := m.addEvent(ctx, value.ID, events.PolicyDeny, "home", resource.GuestPath, "resource absent", &deny, nil); err != nil {
			return m.fail(ctx, value, err)
		}
	}

	if err := m.addEvent(ctx, value.ID, events.ProcessStart, request.Runtime.Command[0], "/workspace", "execute", nil, map[string]any{
		"argv":                request.Runtime.Command,
		"workspace_read_only": request.Runtime.WorkspaceReadOnly,
		"network":             value.NetworkMode,
		"home":                request.HomePolicy,
	}); err != nil {
		return m.fail(ctx, value, err)
	}

	result, runErr := m.runner.Run(ctx, request.Runtime)
	// Cancellation stops the untrusted process, but it must not prevent Ghost
	// from recording the terminal session state and evidence already collected.
	finalizeCtx, cancelFinalize := finalizationContext(ctx)
	defer cancelFinalize()
	type observation struct {
		sequence int
		access   *ghruntime.AccessEvidence
		network  *ghruntime.NetworkEvidence
	}
	observations := make([]observation, 0, len(result.Accesses)+len(result.Network))
	for index := range result.Accesses {
		observations = append(observations, observation{sequence: result.Accesses[index].Sequence, access: &result.Accesses[index]})
	}
	for index := range result.Network {
		observations = append(observations, observation{sequence: result.Network[index].Sequence, network: &result.Network[index]})
	}
	sort.SliceStable(observations, func(left, right int) bool { return observations[left].sequence < observations[right].sequence })
	containmentRecorded := false
	for _, observed := range observations {
		if observed.network != nil {
			networkEvent := *observed.network
			metadata := map[string]any{
				"scheme": networkEvent.Scheme, "host": networkEvent.Host, "port": networkEvent.Port,
				"method": networkEvent.Method, "contained": networkEvent.Contained,
			}
			resource := fmt.Sprintf("%s:%d", networkEvent.Host, networkEvent.Port)
			if err := m.addEventAt(finalizeCtx, value.ID, networkEvent.DetectedAt, events.NetworkRequest, "agent", resource, networkEvent.Method, nil, metadata); err != nil {
				return m.fail(finalizeCtx, value, err)
			}
			eventType := events.NetworkDeny
			if networkEvent.Decision == policy.Allow {
				eventType = events.NetworkAllow
			}
			decision := networkEvent.Decision
			if err := m.addEventAt(finalizeCtx, value.ID, networkEvent.DetectedAt, eventType, "gateway", resource, "enforce destination policy", &decision, metadata); err != nil {
				return m.fail(finalizeCtx, value, err)
			}
			continue
		}

		access := *observed.access
		decoy, ok := decoyByID[access.DecoyID]
		if !ok {
			return m.fail(ctx, value, fmt.Errorf("runtime returned evidence for unknown decoy %q", access.DecoyID))
		}
		changed, triggerErr := m.store.TriggerDecoy(finalizeCtx, value.ID, access.DecoyID, access.DetectedAt)
		if triggerErr != nil {
			return m.fail(finalizeCtx, value, triggerErr)
		}
		if !changed {
			continue
		}
		shadow := policy.Shadow
		metadata := map[string]any{"decoy_id": access.DecoyID, "sentinel_events": access.Events}
		if err := m.addEventAt(finalizeCtx, value.ID, access.DetectedAt, events.DecoyAccess, "agent", decoy.GuestPath, "open/access", &shadow, metadata); err != nil {
			return m.fail(finalizeCtx, value, err)
		}
		if request.ContainOnDecoy && result.Contained && !containmentRecorded {
			containmentRecorded = true
			value.Contained = true
			if err := m.addEventAt(finalizeCtx, value.ID, access.DetectedAt, events.ContainmentActivated, "ghost", "network", "change session network policy", &deny, map[string]any{
				"trigger": events.DecoyAccess, "state": "CONTAINED",
			}); err != nil {
				return m.fail(finalizeCtx, value, err)
			}
		}
		if request.RecordIncident {
			incidentMetadata := map[string]any{
				"decoy_id": access.DecoyID,
				"severity": request.IncidentSeverity,
			}
			if err := m.addEventAt(finalizeCtx, value.ID, access.DetectedAt, events.SecurityIncident, "agent", decoy.GuestPath, "shadow resource accessed", &shadow, incidentMetadata); err != nil {
				return m.fail(finalizeCtx, value, err)
			}
		}
	}
	if result.Contained && !value.Contained {
		return m.fail(finalizeCtx, value, fmt.Errorf("runtime reported containment without decoy access evidence"))
	}
	if result.Started {
		exitCode := result.ExitCode
		value.ExitCode = &exitCode
		metadata := map[string]any{"exit_code": exitCode}
		if runErr != nil {
			metadata["runtime_error"] = runErr.Error()
		}
		if err := m.addEvent(finalizeCtx, value.ID, events.ProcessExit, request.Runtime.Command[0], "/workspace", "exit", nil, metadata); err != nil {
			return m.fail(finalizeCtx, value, err)
		}
	}

	completedAt := m.now()
	value.CompletedAt = &completedAt
	if runErr != nil || value.ExitCode == nil || *value.ExitCode != 0 {
		value.Status = Failed
	} else {
		value.Status = Completed
	}
	if err := m.store.UpdateSession(finalizeCtx, value); err != nil {
		return value, err
	}
	metadata := map[string]any{"status": value.Status}
	if value.ExitCode != nil {
		metadata["exit_code"] = *value.ExitCode
	}
	if runErr != nil {
		metadata["error"] = runErr.Error()
	}
	if err := m.addEvent(finalizeCtx, value.ID, events.SessionEnd, "ghost", "", string(value.Status), nil, metadata); err != nil {
		return value, err
	}
	return value, runErr
}

func evaluateHomeResources(request RunRequest) ([]deception.Resource, map[string]policy.Decision, error) {
	resources := deception.KnownResources()
	selected := make([]deception.Resource, 0, len(resources))
	decisions := make(map[string]policy.Decision, len(resources))
	for index := range resources {
		switch resources[index].Type {
		case deception.AWSCredentials:
			resources[index].Enabled = request.Resources.AWSCredentials
		case deception.SSHPrivateKey:
			resources[index].Enabled = request.Resources.SSHPrivateKey
		case deception.EnvFile:
			resources[index].Enabled = request.Resources.EnvFile
		}
		decision, err := policy.HomeResourceDecision(request.HomePolicy, request.DeceptionEnabled, resources[index].Enabled)
		if err != nil {
			return nil, nil, err
		}
		decisions[resources[index].GuestPath] = decision
		if decision == policy.Shadow {
			resources[index].Enabled = true
			selected = append(selected, resources[index])
		}
	}
	return selected, decisions, nil
}

func (m *Manager) fail(ctx context.Context, value Session, cause error) (Session, error) {
	finalizeCtx, cancel := finalizationContext(ctx)
	defer cancel()
	completedAt := m.now()
	value.CompletedAt = &completedAt
	value.Status = Failed
	if err := m.store.UpdateSession(finalizeCtx, value); err != nil {
		return value, fmt.Errorf("%v; persist failed session: %w", cause, err)
	}
	if err := m.addEvent(finalizeCtx, value.ID, events.SessionEnd, "ghost", "", string(value.Status), nil, map[string]any{"error": cause.Error(), "status": value.Status}); err != nil {
		return value, fmt.Errorf("%v; persist session end: %w", cause, err)
	}
	return value, cause
}

func finalizationContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
}

func (m *Manager) addEvent(ctx context.Context, sessionID string, eventType events.Type, subject, resource, action string, decision *policy.Decision, metadata map[string]any) error {
	return m.addEventAt(ctx, sessionID, m.now(), eventType, subject, resource, action, decision, metadata)
}

func (m *Manager) addEventAt(ctx context.Context, sessionID string, timestamp time.Time, eventType events.Type, subject, resource, action string, decision *policy.Decision, metadata map[string]any) error {
	event := &events.Event{
		SessionID: sessionID,
		Timestamp: timestamp,
		Type:      eventType,
		Subject:   subject,
		Resource:  resource,
		Action:    action,
		Decision:  decision,
		Metadata:  metadata,
	}
	return m.store.AddEvent(ctx, event)
}
