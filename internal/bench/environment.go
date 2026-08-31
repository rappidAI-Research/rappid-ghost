package bench

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/deception"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	"github.com/rappidAI-research/rappid-ghost/internal/incidents"
	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
	"github.com/rappidAI-research/rappid-ghost/internal/provenance"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
	"github.com/rappidAI-research/rappid-ghost/internal/storage"
)

type environment struct {
	dockerBinary      string
	dockerUnavailable string
	fixture           *httpFixture
	fixtureErr        error
}

func (e *environment) close() error {
	if e.fixture != nil {
		err := e.fixture.close()
		e.fixture = nil
		return err
	}
	return nil
}

func (e *environment) requireFixture(ctx context.Context) (*httpFixture, error) {
	if e.fixture != nil || e.fixtureErr != nil {
		return e.fixture, e.fixtureErr
	}
	e.fixture, e.fixtureErr = startHTTPFixture(ctx, e.dockerBinary)
	return e.fixture, e.fixtureErr
}

type project struct {
	root        string
	workspace   string
	sessionsDir string
	store       *storage.Store
	runner      ghruntime.Runtime
}

type runSpec struct {
	Command          []string
	HomePolicy       string
	Deception        bool
	Resources        session.ResourcePolicy
	Network          ghostnetwork.Policy
	ContainOnDecoy   bool
	RecordIncident   bool
	IncidentSeverity string
}

type observation struct {
	Session   session.Session
	Events    []events.Event
	Decoys    []deception.Decoy
	Graph     provenance.Graph
	Incidents incidents.Report
	Output    string
	RunError  error
}

func newProject(ctx context.Context, runner ghruntime.Runtime) (*project, error) {
	root, err := os.MkdirTemp("", "ghostbench-")
	if err != nil {
		return nil, fmt.Errorf("create benchmark root: %w", err)
	}
	workspace := filepath.Join(root, "workspace")
	sessionsDir := filepath.Join(root, "data", "sessions")
	for _, directory := range []string{workspace, sessionsDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			_ = os.RemoveAll(root)
			return nil, fmt.Errorf("create benchmark directory: %w", err)
		}
	}
	store, err := storage.Open(ctx, filepath.Join(root, "data", "ghost.db"))
	if err != nil {
		_ = os.RemoveAll(root)
		return nil, err
	}
	return &project{root: root, workspace: workspace, sessionsDir: sessionsDir, store: store, runner: runner}, nil
}

func (p *project) close() error {
	var result error
	if p.store != nil {
		result = p.store.Close()
	}
	if err := os.RemoveAll(p.root); err != nil {
		result = errors.Join(result, err)
	}
	return result
}

func (p *project) run(ctx context.Context, spec runSpec) (observation, error) {
	if spec.HomePolicy == "" {
		spec.HomePolicy = "deny"
	}
	if spec.Network.Mode == "" {
		var err error
		spec.Network, err = ghostnetwork.NewPolicy("deny", nil)
		if err != nil {
			return observation{}, err
		}
	}
	if spec.IncidentSeverity == "" {
		spec.IncidentSeverity = "high"
	}
	var output bytes.Buffer
	manager := session.NewManager(p.store, p.runner)
	value, runErr := manager.Run(ctx, session.RunRequest{
		Runtime: ghruntime.RunRequest{
			Command: spec.Command, Workspace: p.workspace,
			Stdout: &output, Stderr: &output,
		},
		SessionsDir: p.sessionsDir, HomePolicy: spec.HomePolicy,
		DeceptionEnabled: spec.Deception, Resources: spec.Resources,
		IncidentSeverity: spec.IncidentSeverity, RecordIncident: spec.RecordIncident,
		NetworkPolicy: spec.Network, ContainOnDecoy: spec.ContainOnDecoy,
	})
	storedEvents, eventErr := p.store.Events(context.WithoutCancel(ctx), value.ID)
	if eventErr != nil {
		return observation{}, eventErr
	}
	decoys, decoyErr := p.store.Decoys(context.WithoutCancel(ctx), value.ID)
	if decoyErr != nil {
		return observation{}, decoyErr
	}
	graph := provenance.Build(value, storedEvents)
	return observation{
		Session: value, Events: storedEvents, Decoys: decoys, Graph: graph,
		Incidents: incidents.Reconstruct(value, storedEvents), Output: output.String(), RunError: runErr,
	}, nil
}

func (o observation) evidence() EvidenceBundle {
	bundle := EvidenceBundle{SessionID: o.Session.ID}
	for _, event := range o.Events {
		bundle.EventIDs = append(bundle.EventIDs, event.ID)
	}
	for _, incident := range o.Incidents.Incidents {
		bundle.IncidentIDs = append(bundle.IncidentIDs, incident.ID)
	}
	for _, node := range o.Graph.Nodes {
		bundle.ProvenanceNodeIDs = append(bundle.ProvenanceNodeIDs, node.ID)
	}
	for _, edge := range o.Graph.Edges {
		bundle.ProvenanceEdgeIDs = append(bundle.ProvenanceEdgeIDs, edge.ID)
	}
	if bundle.EventIDs == nil {
		bundle.EventIDs = []int64{}
	}
	if bundle.IncidentIDs == nil {
		bundle.IncidentIDs = []string{}
	}
	if bundle.ProvenanceNodeIDs == nil {
		bundle.ProvenanceNodeIDs = []string{}
	}
	if bundle.ProvenanceEdgeIDs == nil {
		bundle.ProvenanceEdgeIDs = []string{}
	}
	return bundle
}

type httpFixture struct {
	binary  string
	network string
	name    string
	ip      string
}

func startHTTPFixture(ctx context.Context, binary string) (*httpFixture, error) {
	suffix, err := randomSuffix()
	if err != nil {
		return nil, err
	}
	fixture := &httpFixture{
		binary: binary, network: "ghost-bench-upstream-" + suffix,
		name: "ghost-bench-http-" + suffix,
	}
	if _, err := fixture.command(ctx, fixture.networkArguments()...); err != nil {
		return nil, fmt.Errorf("create local fixture network: %w", err)
	}
	// Keep the fixture within Alpine's base BusyBox applets. The response is
	// written directly to each accepted connection, avoiding nc -e handler
	// behavior that can leave an HTTP client waiting indefinitely.
	fixtureCommand := fixtureServerCommand()
	if _, err := fixture.command(ctx, fixture.runArguments(fixtureCommand)...); err != nil {
		return nil, errors.Join(fmt.Errorf("start local HTTP fixture: %w", err), fixture.close())
	}
	deadline := time.Now().Add(10 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		if fixture.healthy(ctx) {
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), fixture.close())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !ready {
		return nil, errors.Join(fixture.readinessError(), fixture.close())
	}
	output, err := fixture.command(ctx, "inspect", "--format",
		"{{(index .NetworkSettings.Networks \""+fixture.network+"\").IPAddress}}", fixture.name)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("inspect local fixture: %w", err), fixture.close())
	}
	fixture.ip = strings.TrimSpace(output)
	if net.ParseIP(fixture.ip) == nil {
		return nil, errors.Join(errors.New("local HTTP fixture has no valid address"), fixture.close())
	}
	return fixture, nil
}

func (f *httpFixture) networkArguments() []string {
	return []string{
		"network", "create", "--driver", "bridge", "--internal",
		"--label", "ghost.component=benchmark-fixture", f.network,
	}
}

func (f *httpFixture) runArguments(command string) []string {
	return []string{
		"run", "--detach", "--name", f.name,
		"--label", "ghost.component=benchmark-fixture", "--network", f.network,
		"--network-alias", "allowed.test", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--pids-limit", "32",
		"--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=4m",
		ghruntime.DefaultDockerImage, "sh", "-c", command,
	}
}

func (f *httpFixture) healthy(ctx context.Context) bool {
	// A probe must have its own deadline. The scenario context can last two
	// minutes; using it directly previously turned one unhealthy fixture into a
	// two-minute blocked docker exec and obscured the startup failure.
	probeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_, err := f.command(probeCtx, f.readinessArguments()...)
	return err == nil
}

func fixtureServerCommand() string {
	return `while true; do printf 'HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nallowed\n' | busybox nc -l -p 80 || exit; done`
}

func (f *httpFixture) readinessArguments() []string {
	return []string{"exec", f.name, "wget", "-T", "1", "-qO-", "http://127.0.0.1/"}
}

func (f *httpFixture) readinessError() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	state, stateErr := f.command(ctx, "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}} {{.State.Error}}", f.name)
	logs, logsErr := f.command(ctx, "logs", f.name)
	if stateErr != nil {
		return fmt.Errorf("local HTTP fixture did not become ready (inspect failed: %w)", stateErr)
	}
	if logsErr != nil {
		return fmt.Errorf("local HTTP fixture did not become ready (state=%s; logs unavailable: %w)", strings.TrimSpace(state), logsErr)
	}
	return fmt.Errorf("local HTTP fixture did not become ready (state=%s; logs=%s)", strings.TrimSpace(state), lastLine(logs))
}

func (f *httpFixture) command(ctx context.Context, arguments ...string) (string, error) {
	output, err := exec.CommandContext(ctx, f.binary, arguments...).CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("docker %s: %w: %s", strings.Join(arguments, " "), err, lastLine(string(output)))
	}
	return string(output), nil
}

func (f *httpFixture) close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var result error
	if f.name != "" {
		if _, err := f.command(ctx, "rm", "--force", f.name); err != nil && !strings.Contains(err.Error(), "No such container") {
			result = errors.Join(result, err)
		}
	}
	if f.network != "" {
		if _, err := f.command(ctx, "network", "rm", f.network); err != nil && !strings.Contains(err.Error(), "not found") {
			result = errors.Join(result, err)
		}
	}
	return result
}

func randomSuffix() (string, error) {
	value := make([]byte, 6)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate benchmark fixture ID: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func lastLine(value string) string {
	lines := strings.Split(strings.TrimSpace(value), "\n")
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[len(lines)-1])
}
