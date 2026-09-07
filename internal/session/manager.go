package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/rappidAI-research/rappid-ghost/internal/deception"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	"github.com/rappidAI-research/rappid-ghost/internal/promptguard"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
	"github.com/rappidAI-research/rappid-ghost/internal/trust"
)

type EventStore interface {
	CreateSession(ctx context.Context, value Session) error
	UpdateSession(ctx context.Context, value Session) error
	IncompleteSessions(ctx context.Context) ([]Session, error)
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
	SecurityNotice   func(SecurityNotice)
}

type SecurityNotice struct {
	Type    events.Type
	Sources int
}

type Manager struct {
	store     EventStore
	runner    ghruntime.Runtime
	generator *deception.Generator
	signals   *events.Pipeline
	inspector promptguard.Inspector
	now       func() time.Time
}

func NewManager(store EventStore, runner ghruntime.Runtime) *Manager {
	return &Manager{
		store: store, runner: runner, generator: deception.NewGenerator(), signals: events.NewPipeline(store), inspector: promptguard.New(),
		now: func() time.Time { return time.Now().UTC() },
	}
}

// NewManagerWithInspector exposes the same orchestration path with an explicit
// workspace inspector for focused tests. A nil inspector remains fail closed.
func NewManagerWithInspector(store EventStore, runner ghruntime.Runtime, inspector promptguard.Inspector) *Manager {
	manager := NewManager(store, runner)
	manager.inspector = inspector
	return manager
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
	runLock, err := acquireRunLock(request.SessionsDir)
	if err != nil {
		return Session{}, err
	}
	defer runLock.Close()
	if err := m.recoverInterrupted(ctx); err != nil {
		return Session{}, err
	}
	id, err := NewID()
	if err != nil {
		return Session{}, err
	}
	value := Session{
		ID:            id,
		CreatedAt:     m.now(),
		Command:       append([]string(nil), request.Runtime.Command...),
		Runtime:       m.runner.Name(),
		Status:        Created,
		NetworkMode:   request.NetworkPolicy.Mode,
		SecurityState: policy.StateNormal,
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

	securityContext, err := m.inspectWorkspace(ctx, value.ID, request)
	if err != nil {
		return m.fail(ctx, value, err)
	}

	allow := policy.Allow
	deny := policy.Deny
	if err := m.addEvent(ctx, value.ID, events.PolicyAllow, "workspace", "/workspace", "expose", &allow, map[string]any{
		"trust_class": trust.Untrusted,
	}); err != nil {
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

	shadowResources, decisions, err := evaluateHomeResources(request, securityContext)
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
			"decoy_id": decoy.ID, "type": decoy.Type,
			"trust_class": trust.Shadow, "protected_resource_class": trust.Sensitive,
		}); err != nil {
			return m.fail(ctx, value, err)
		}
		shadow := policy.Shadow
		if err := m.addEvent(ctx, value.ID, events.PolicyShadow, "home", decoy.GuestPath, "expose synthetic resource", &shadow, map[string]any{
			"decoy_id": decoy.ID, "type": decoy.Type,
			"trust_class": trust.Shadow, "protected_resource_class": trust.Sensitive,
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
		if err := m.addEvent(ctx, value.ID, events.PolicyDeny, "home", resource.GuestPath, "resource absent", &deny, map[string]any{
			"trust_class": trust.Sensitive,
		}); err != nil {
			return m.fail(ctx, value, err)
		}
	}

	processStartedAt := m.now()
	if err := m.addEventAt(ctx, value.ID, processStartedAt, events.ProcessStart, request.Runtime.Command[0], "/workspace", "execute", nil, map[string]any{
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
	if result.Started && !result.SecurityState.Valid() {
		return m.fail(finalizeCtx, value, fmt.Errorf("runtime returned invalid security state %q", result.SecurityState))
	}
	if result.SecurityState.IsContained() {
		if err := value.TransitionSecurityState(policy.StateContained); err != nil {
			return m.fail(finalizeCtx, value, fmt.Errorf("apply runtime containment: %w", err))
		}
	}
	for _, access := range result.Accesses {
		decoy, ok := decoyByID[access.DecoyID]
		if !ok || access.GuestPath != decoy.GuestPath {
			return m.fail(finalizeCtx, value, fmt.Errorf("runtime returned evidence for unknown decoy %q", access.DecoyID))
		}
	}
	if value.IsContained() && (!request.ContainOnDecoy || len(result.Accesses) == 0) {
		return m.fail(finalizeCtx, value, fmt.Errorf("runtime reported containment without matching decoy access evidence"))
	}
	if request.ContainOnDecoy && len(result.Accesses) > 0 && !value.IsContained() {
		return m.fail(finalizeCtx, value, fmt.Errorf("runtime returned decoy access evidence without required containment state"))
	}
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
			detectedAt, timestampErr := runtimeEvidenceTime(networkEvent.DetectedAt, processStartedAt)
			if timestampErr != nil {
				return m.fail(finalizeCtx, value, timestampErr)
			}
			if networkEvent.Decision != policy.Allow && networkEvent.Decision != policy.Deny {
				return m.fail(finalizeCtx, value, fmt.Errorf("runtime returned invalid network decision %q", networkEvent.Decision))
			}
			effective, policyErr := policy.Evaluate(networkEvent.Decision,
				securityContext.evaluation(policy.ResourceNetwork, trust.Untrusted, networkEvent.SecurityState))
			if policyErr != nil {
				return m.fail(finalizeCtx, value, fmt.Errorf("runtime returned invalid network security context: %w", policyErr))
			}
			if effective != networkEvent.Decision {
				return m.fail(finalizeCtx, value, fmt.Errorf("runtime reported %s network decision while session state requires %s", networkEvent.Decision, effective))
			}
			metadata := map[string]any{
				"scheme": networkEvent.Scheme, "host": networkEvent.Host, "port": networkEvent.Port,
				"method": networkEvent.Method, "contained": networkEvent.SecurityState.IsContained(),
			}
			resource := fmt.Sprintf("%s:%d", networkEvent.Host, networkEvent.Port)
			if err := m.addEventAt(finalizeCtx, value.ID, detectedAt, events.NetworkRequest, "agent", resource, networkEvent.Method, nil, metadata); err != nil {
				return m.fail(finalizeCtx, value, err)
			}
			eventType := events.NetworkDeny
			if networkEvent.Decision == policy.Allow {
				eventType = events.NetworkAllow
			}
			decision := networkEvent.Decision
			if err := m.addEventAt(finalizeCtx, value.ID, detectedAt, eventType, "gateway", resource, "enforce destination policy", &decision, metadata); err != nil {
				return m.fail(finalizeCtx, value, err)
			}
			continue
		}

		access := *observed.access
		detectedAt, timestampErr := runtimeEvidenceTime(access.DetectedAt, processStartedAt)
		if timestampErr != nil {
			return m.fail(finalizeCtx, value, timestampErr)
		}
		decoy, ok := decoyByID[access.DecoyID]
		if !ok {
			return m.fail(ctx, value, fmt.Errorf("runtime returned evidence for unknown decoy %q", access.DecoyID))
		}
		changed, triggerErr := m.store.TriggerDecoy(finalizeCtx, value.ID, access.DecoyID, detectedAt)
		if triggerErr != nil {
			return m.fail(finalizeCtx, value, triggerErr)
		}
		if !changed {
			continue
		}
		shadow := policy.Shadow
		metadata := map[string]any{
			"decoy_id": access.DecoyID, "sentinel_events": access.Events,
			"trust_class": trust.Shadow, "protected_resource_class": trust.Sensitive,
		}
		accessEvent, err := m.recordEventAt(finalizeCtx, value.ID, detectedAt, events.DecoyAccess, "agent", decoy.GuestPath, "open/access", &shadow, metadata)
		if err != nil {
			return m.fail(finalizeCtx, value, err)
		}
		if err := m.addEventAt(finalizeCtx, value.ID, detectedAt, events.SensitiveResourceRequest, "agent", decoy.GuestPath, "request protected resource path", &shadow, map[string]any{
			"decoy_id": access.DecoyID, "source_event_id": accessEvent.ID,
			"trust_class": trust.Sensitive, "observed_via": events.DecoyAccess,
		}); err != nil {
			return m.fail(finalizeCtx, value, err)
		}
		securityContext.observeShadowAccess()
		if request.ContainOnDecoy && value.IsContained() && !containmentRecorded {
			containmentRecorded = true
			if err := m.addEventAt(finalizeCtx, value.ID, detectedAt, events.ContainmentActivated, "ghost", "network", "change session network policy", &deny, map[string]any{
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
			if err := m.addEventAt(finalizeCtx, value.ID, detectedAt, events.SecurityIncident, "agent", decoy.GuestPath, "shadow resource accessed", &shadow, incidentMetadata); err != nil {
				return m.fail(finalizeCtx, value, err)
			}
		}
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

func (m *Manager) recoverInterrupted(ctx context.Context) error {
	interrupted, err := m.store.IncompleteSessions(ctx)
	if err != nil {
		return fmt.Errorf("find interrupted sessions: %w", err)
	}
	if len(interrupted) == 0 {
		return nil
	}
	recoverer, ok := m.runner.(ghruntime.Recoverer)
	if !ok {
		return errors.New("runtime cannot safely recover interrupted sessions")
	}
	ids := make([]string, len(interrupted))
	for index := range interrupted {
		ids[index] = interrupted[index].ID
	}
	if err := recoverer.Recover(ctx, ids); err != nil {
		return fmt.Errorf("recover interrupted runtime resources: %w", err)
	}

	for index := range interrupted {
		completedAt := m.now()
		interrupted[index].CompletedAt = &completedAt
		interrupted[index].Status = Failed
		if err := m.store.UpdateSession(ctx, interrupted[index]); err != nil {
			return fmt.Errorf("finalize interrupted session %s: %w", interrupted[index].ID, err)
		}
		if err := m.addEventAt(ctx, interrupted[index].ID, completedAt, events.SessionEnd, "ghost", "", "recover interrupted session", nil, map[string]any{
			"recovered": true,
			"reason":    "previous Ghost run ended before terminal persistence",
			"status":    Failed,
		}); err != nil {
			return fmt.Errorf("record interrupted session recovery %s: %w", interrupted[index].ID, err)
		}
	}
	return nil
}

type projectRunLock struct {
	file *os.File
}

func acquireRunLock(sessionsDir string) (*projectRunLock, error) {
	if sessionsDir == "" {
		return nil, errors.New("sessions directory is required")
	}
	info, err := os.Lstat(sessionsDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("sessions directory must be a real directory")
	}
	path := filepath.Join(sessionsDir, ".run.lock")
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, errors.New("Ghost run lock must be a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect Ghost run lock: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open Ghost run lock: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure Ghost run lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("another Ghost run is active for this project")
		}
		return nil, fmt.Errorf("lock Ghost project run: %w", err)
	}
	return &projectRunLock{file: file}, nil
}

func (l *projectRunLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	return errors.Join(unlockErr, closeErr)
}

func evaluateHomeResources(request RunRequest, securityContext runSecurityContext) ([]deception.Resource, map[string]policy.Decision, error) {
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
		base, err := policy.HomeResourceDecision(request.HomePolicy, request.DeceptionEnabled, resources[index].Enabled)
		if err != nil {
			return nil, nil, err
		}
		resourceTrust := trust.Sensitive
		if base == policy.Shadow {
			resourceTrust = trust.Shadow
		}
		decision, err := policy.Evaluate(base, securityContext.evaluation(policy.ResourceHome, resourceTrust, policy.StateNormal))
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

func (m *Manager) inspectWorkspace(ctx context.Context, sessionID string, request RunRequest) (runSecurityContext, error) {
	var securityContext runSecurityContext
	if m.inspector == nil {
		return securityContext, errors.New("prompt guard workspace inspector is unavailable")
	}
	report, err := m.inspector.Inspect(ctx, request.Runtime.Workspace)
	if err != nil {
		return securityContext, fmt.Errorf("inspect workspace for suspicious instructions: %w", err)
	}
	if err := report.Validate(); err != nil {
		return securityContext, fmt.Errorf("validate workspace inspection: %w", err)
	}
	recordedSources := make(map[string]bool, len(report.Sources)+len(report.Findings))
	for _, source := range report.Sources {
		resource, resourceErr := workspaceResource(source.Path)
		if resourceErr != nil {
			return securityContext, resourceErr
		}
		if recordedSources[resource] {
			return securityContext, fmt.Errorf("prompt guard returned duplicate source %q", source.Path)
		}
		recordedSources[resource] = true
		if err := m.addEvent(ctx, sessionID, events.UntrustedContentObserved, "prompt_guard", resource, "observe selected workspace text", nil, map[string]any{
			"content_sha256": source.Fingerprint, "source_kind": string(source.Kind), "trust_class": trust.Untrusted,
		}); err != nil {
			return securityContext, err
		}
		securityContext.observeUntrustedInput()
	}
	for _, finding := range report.Findings {
		resource, resourceErr := workspaceResource(finding.SourcePath)
		if resourceErr != nil {
			return securityContext, resourceErr
		}
		if !recordedSources[resource] {
			return securityContext, fmt.Errorf("prompt guard finding has no matching source %q", finding.SourcePath)
		}
		categories := make([]string, len(finding.Categories))
		for index, category := range finding.Categories {
			categories[index] = string(category)
		}
		if err := m.addEvent(ctx, sessionID, events.PromptInjectionSuspected, "workspace", resource, "detect suspicious instructions", nil, map[string]any{
			"categories":        categories,
			"content_sha256":    finding.Fingerprint,
			"window_start_line": finding.Line,
			"rule_ids":          append([]string(nil), finding.RuleIDs...),
			"severity":          string(finding.Severity),
			"source_kind":       string(finding.SourceKind),
			"trust_class":       trust.Untrusted,
		}); err != nil {
			return securityContext, err
		}
		severity, severityErr := promptTrustSeverity(string(finding.Severity))
		if severityErr != nil {
			return securityContext, severityErr
		}
		if err := securityContext.observePromptFinding(severity); err != nil {
			return securityContext, err
		}
	}
	if report.Limited() {
		if err := m.addEvent(ctx, sessionID, events.ResourceLimitTriggered, "prompt_guard", "workspace:/workspace", "bound workspace inspection", nil, map[string]any{
			"analysis_truncated":  report.AnalysisTruncated,
			"discovery_truncated": report.DiscoveryTruncated,
			"skipped_byte_limit":  report.SkippedByByteLimit,
			"skipped_file_limit":  report.SkippedByFileLimit,
			"skipped_oversized":   report.SkippedOversized,
		}); err != nil {
			return securityContext, err
		}
	}
	if len(report.Findings) == 0 {
		return securityContext, nil
	}
	if request.SecurityNotice != nil {
		request.SecurityNotice(SecurityNotice{Type: events.PromptInjectionSuspected, Sources: len(report.Findings)})
	}
	return securityContext, nil
}

func workspaceResource(relative string) (string, error) {
	value := filepath.ToSlash(strings.TrimSpace(relative))
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("prompt guard returned unsafe source path %q", relative)
	}
	clean := path.Clean(value)
	if clean == "." || clean != value || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("prompt guard returned unsafe source path %q", relative)
	}
	return "workspace:" + clean, nil
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

// BusyBox sidecars currently report whole-second Unix timestamps. Clamp valid
// runtime evidence to PROCESS_START so coarse timestamps cannot sort observed
// in-container activity before the process that produced it. Sequence and
// stable event IDs retain ordering among observations at the same timestamp.
func runtimeEvidenceTime(reported, processStartedAt time.Time) (time.Time, error) {
	if reported.IsZero() {
		return time.Time{}, errors.New("runtime returned evidence without a timestamp")
	}
	reported = reported.UTC()
	if reported.Before(processStartedAt) {
		return processStartedAt, nil
	}
	return reported, nil
}

func (m *Manager) addEvent(ctx context.Context, sessionID string, eventType events.Type, subject, resource, action string, decision *policy.Decision, metadata map[string]any) error {
	return m.addEventAt(ctx, sessionID, m.now(), eventType, subject, resource, action, decision, metadata)
}

func (m *Manager) addEventAt(ctx context.Context, sessionID string, timestamp time.Time, eventType events.Type, subject, resource, action string, decision *policy.Decision, metadata map[string]any) error {
	_, err := m.recordEventAt(ctx, sessionID, timestamp, eventType, subject, resource, action, decision, metadata)
	return err
}

func (m *Manager) recordEventAt(ctx context.Context, sessionID string, timestamp time.Time, eventType events.Type, subject, resource, action string, decision *policy.Decision, metadata map[string]any) (*events.Event, error) {
	return m.signals.Record(ctx, sessionID, events.Signal{
		Timestamp: timestamp,
		Type:      eventType,
		Subject:   subject,
		Resource:  resource,
		Action:    action,
		Decision:  decision,
		Metadata:  metadata,
	})
}
