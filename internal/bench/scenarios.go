package bench

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rappidAI-research/rappid-ghost/internal/config"
	"github.com/rappidAI-research/rappid-ghost/internal/deception"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	"github.com/rappidAI-research/rappid-ghost/internal/incidents"
	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	"github.com/rappidAI-research/rappid-ghost/internal/provenance"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
)

func scenarioDefinitions() []scenarioDefinition {
	return []scenarioDefinition{
		{ID: "host-home-isolation", Name: "Host home isolation", Property: "A controlled host-only resource outside the workspace is unavailable to the guest.", RequiresDocker: true, Run: scenarioHostIsolation},
		{ID: "shadow-credentials", Name: "Shadow credentials", Property: "The guest receives synthetic AWS credentials and access produces stored evidence.", RequiresDocker: true, Run: scenarioShadowCredentials},
		{ID: "deny-sensitive-resource", Name: "Sensitive resource deny", Property: "DENY leaves the selected synthetic-home resource absent.", RequiresDocker: true, Run: scenarioDenyResource},
		{ID: "network-deny", Name: "Network deny", Property: "A guest in network DENY mode cannot reach the controlled HTTP fixture.", RequiresDocker: true, RequiresFixture: true, Run: scenarioNetworkDeny},
		{ID: "network-allowlist", Name: "Network allowlist", Property: "An exact allowed hostname succeeds while an unapproved hostname is denied.", RequiresDocker: true, RequiresFixture: true, Run: scenarioNetworkAllowlist},
		{ID: "direct-egress-bypass", Name: "Direct egress bypass", Property: "Unsetting proxy variables and using a raw IP from a child process does not restore egress.", RequiresDocker: true, RequiresFixture: true, Run: scenarioDirectBypass},
		{ID: "dynamic-containment", Name: "Dynamic containment", Property: "A decoy access activates containment before a later allowed-host request is denied.", RequiresDocker: true, RequiresFixture: true, Run: scenarioDynamicContainment},
		{ID: "session-isolation", Name: "Session isolation", Property: "Containment, decoys, events, provenance, and incidents remain scoped to their session.", RequiresDocker: true, RequiresFixture: true, Run: scenarioSessionIsolation},
		{ID: "fail-closed-runtime", Name: "Fail-closed runtime", Property: "An unavailable Docker executable and invalid policy do not trigger host execution.", Run: scenarioFailClosed},
		{ID: "safe-baseline", Name: "Safe baseline", Property: "A harmless command completes without false decoy access, containment, or incidents.", RequiresDocker: true, Run: scenarioSafeBaseline},
	}
}

func denyPolicy() ghostnetwork.Policy {
	value, _ := ghostnetwork.NewPolicy("deny", nil)
	return value
}

func allowPolicy() ghostnetwork.Policy {
	value, _ := ghostnetwork.NewPolicy("allowlist", []string{"allowed.test"})
	return value
}

func awsResources() session.ResourcePolicy {
	return session.ResourcePolicy{AWSCredentials: true}
}

func dockerFor(e *environment, upstream string) *ghruntime.DockerRuntime {
	return ghruntime.NewDockerWithOptions(ghruntime.DockerOptions{
		Binary: e.dockerBinary, GatewayNetwork: upstream,
	})
}

func scenarioHostIsolation(ctx context.Context, e *environment) Result {
	hostRoot, err := os.MkdirTemp("", "ghostbench-host-only-")
	if err != nil {
		return failf("create controlled host fixture: %v", err)
	}
	defer os.RemoveAll(hostRoot)
	fixture := filepath.Join(hostRoot, "host-only.txt")
	const fixtureValue = "GHOSTBENCH_CONTROLLED_HOST_FIXTURE"
	if err := os.WriteFile(fixture, []byte(fixtureValue), 0o600); err != nil {
		return failf("write controlled host fixture: %v", err)
	}

	project, err := newProject(ctx, dockerFor(e, ""))
	if err != nil {
		return failf("prepare benchmark project: %v", err)
	}
	defer project.close()
	observed, err := project.run(ctx, runSpec{
		Command:    []string{"sh", "-c", `test ! -e "$1"`, "ghostbench", fixture},
		HomePolicy: "deny", Network: denyPolicy(),
	})
	if err != nil {
		return failf("collect host-isolation evidence: %v", err)
	}
	data, fixtureErr := os.ReadFile(fixture)
	if observed.RunError != nil || !completedWithZero(observed) || fixtureErr != nil || string(data) != fixtureValue {
		return failWithEvidence("controlled host-only fixture was visible, changed, or the isolated check did not complete", observed.evidence())
	}
	return pass("controlled host-only fixture remained unavailable and unchanged", observed.evidence())
}

func scenarioShadowCredentials(ctx context.Context, e *environment) Result {
	hostRoot, err := os.MkdirTemp("", "ghostbench-host-aws-")
	if err != nil {
		return failf("create controlled host fixture: %v", err)
	}
	defer os.RemoveAll(hostRoot)
	hostCredential := filepath.Join(hostRoot, ".aws", "credentials")
	if err := os.MkdirAll(filepath.Dir(hostCredential), 0o700); err != nil {
		return failf("create controlled credential fixture: %v", err)
	}
	const hostValue = "GHOSTBENCH_CONTROLLED_HOST_AWS_VALUE"
	if err := os.WriteFile(hostCredential, []byte(hostValue), 0o600); err != nil {
		return failf("write controlled credential fixture: %v", err)
	}

	project, err := newProject(ctx, dockerFor(e, ""))
	if err != nil {
		return failf("prepare benchmark project: %v", err)
	}
	defer project.close()
	observed, err := project.run(ctx, runSpec{
		Command:    []string{"sh", "-c", `cat "$HOME/.aws/credentials"`},
		HomePolicy: "shadow", Deception: true, Resources: awsResources(),
		Network: denyPolicy(), RecordIncident: true,
	})
	if err != nil {
		return failf("collect Shadow evidence: %v", err)
	}
	if observed.RunError != nil || !completedWithZero(observed) ||
		!strings.Contains(observed.Output, "Ghost synthetic credential") ||
		!strings.Contains(observed.Output, "GHOST_AWS_") || strings.Contains(observed.Output, hostValue) {
		return failWithEvidence("guest did not receive the expected independent synthetic credential", observed.evidence())
	}
	if len(observed.Decoys) != 1 || observed.Decoys[0].Type != deception.AWSCredentials || !observed.Decoys[0].Triggered ||
		!hasEvent(observed.Events, events.DecoyAccess) || !hasEdge(observed.Graph, provenance.Accessed) || len(observed.Incidents.Incidents) == 0 {
		return failWithEvidence("synthetic credential access lacked decoy, event, provenance, or incident evidence", observed.evidence())
	}
	return pass("synthetic AWS material was returned; DECOY_ACCESS, provenance, and incident evidence were recorded", observed.evidence())
}

func scenarioDenyResource(ctx context.Context, e *environment) Result {
	project, err := newProject(ctx, dockerFor(e, ""))
	if err != nil {
		return failf("prepare benchmark project: %v", err)
	}
	defer project.close()
	observed, err := project.run(ctx, runSpec{
		Command:    []string{"sh", "-c", `test ! -e "$HOME/.aws/credentials"`},
		HomePolicy: "deny", Deception: true, Resources: awsResources(), Network: denyPolicy(),
	})
	if err != nil {
		return failf("collect DENY evidence: %v", err)
	}
	if observed.RunError != nil || !completedWithZero(observed) || len(observed.Decoys) != 0 || hasEvent(observed.Events, events.PolicyShadow) ||
		!hasDecisionFor(observed.Events, events.PolicyDeny, deception.GuestHome+"/.aws/credentials", policy.Deny) {
		return failWithEvidence("DENY did not leave the sensitive home resource absent with a stored policy decision", observed.evidence())
	}
	return pass("AWS credential path was absent and POLICY_DENY was recorded", observed.evidence())
}

func scenarioNetworkDeny(ctx context.Context, e *environment) Result {
	fixture, err := e.requireFixture(ctx)
	if err != nil {
		return failf("prepare controlled network fixture: %v", err)
	}
	project, err := newProject(ctx, dockerFor(e, ""))
	if err != nil {
		return failf("prepare benchmark project: %v", err)
	}
	defer project.close()
	command := `command -v wget >/dev/null || exit 42; if wget -T 2 -qO- "$1" >/dev/null; then exit 41; fi`
	observed, err := project.run(ctx, runSpec{
		Command:    []string{"sh", "-c", command, "ghostbench", "http://" + fixture.ip},
		HomePolicy: "deny", Network: denyPolicy(),
	})
	if err != nil {
		return failf("collect network DENY evidence: %v", err)
	}
	if observed.RunError != nil || !completedWithZero(observed) || !fixture.healthy(ctx) || hasEvent(observed.Events, events.NetworkAllow) ||
		!hasDecisionFor(observed.Events, events.PolicyDeny, "network", policy.Deny) {
		return failWithEvidence("network DENY did not block the controlled HTTP connection", observed.evidence())
	}
	return pass("controlled HTTP fixture was unreachable under network DENY", observed.evidence())
}

func scenarioNetworkAllowlist(ctx context.Context, e *environment) Result {
	fixture, err := e.requireFixture(ctx)
	if err != nil {
		return failf("prepare controlled network fixture: %v", err)
	}
	project, err := newProject(ctx, dockerFor(e, fixture.network))
	if err != nil {
		return failf("prepare benchmark project: %v", err)
	}
	defer project.close()
	command := `command -v wget >/dev/null || exit 42; wget -qO /tmp/allowed http://allowed.test || exit 43; if wget -T 2 -qO- http://denied.test >/dev/null; then exit 44; fi; grep -qx allowed /tmp/allowed`
	observed, err := project.run(ctx, runSpec{
		Command: []string{"sh", "-c", command}, HomePolicy: "deny", Network: allowPolicy(),
	})
	if err != nil {
		return failf("collect allowlist evidence: %v", err)
	}
	if observed.RunError != nil || !completedWithZero(observed) ||
		!hasNetworkDecision(observed.Events, "allowed.test", policy.Allow) ||
		!hasNetworkDecision(observed.Events, "denied.test", policy.Deny) {
		return failWithEvidence("exact allowlist did not produce both observed ALLOW and DENY outcomes", observed.evidence())
	}
	return pass("allowed.test succeeded and denied.test was denied with stored gateway evidence", observed.evidence())
}

func scenarioDirectBypass(ctx context.Context, e *environment) Result {
	fixture, err := e.requireFixture(ctx)
	if err != nil {
		return failf("prepare controlled network fixture: %v", err)
	}
	project, err := newProject(ctx, dockerFor(e, fixture.network))
	if err != nil {
		return failf("prepare benchmark project: %v", err)
	}
	defer project.close()
	command := fmt.Sprintf(`command -v wget >/dev/null || exit 42; unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy; if sh -c 'wget -T 2 -qO- http://%s >/dev/null'; then exit 44; fi`, fixture.ip)
	observed, err := project.run(ctx, runSpec{
		Command: []string{"sh", "-c", command}, HomePolicy: "deny", Network: allowPolicy(),
	})
	if err != nil {
		return failf("collect direct-egress evidence: %v", err)
	}
	if observed.RunError != nil || !completedWithZero(observed) || !fixture.healthy(ctx) || hasEvent(observed.Events, events.NetworkAllow) || hasEvent(observed.Events, events.NetworkDeny) {
		return failWithEvidence("raw-IP child-process bypass succeeded or unexpectedly reached the proxy gateway", observed.evidence())
	}
	return pass("raw-IP access from a child process failed after all proxy variables were unset", observed.evidence())
}

func scenarioDynamicContainment(ctx context.Context, e *environment) Result {
	fixture, err := e.requireFixture(ctx)
	if err != nil {
		return failf("prepare controlled network fixture: %v", err)
	}
	project, err := newProject(ctx, dockerFor(e, fixture.network))
	if err != nil {
		return failf("prepare benchmark project: %v", err)
	}
	defer project.close()
	command := `wget -qO /tmp/first http://allowed.test && cat "$HOME/.aws/credentials" >/dev/null && if wget -qO /tmp/second http://allowed.test; then exit 40; fi; cat /tmp/first`
	observed, err := project.run(ctx, runSpec{
		Command: []string{"sh", "-c", command}, HomePolicy: "shadow", Deception: true,
		Resources: awsResources(), Network: allowPolicy(), ContainOnDecoy: true, RecordIncident: true,
	})
	if err != nil {
		return failf("collect containment evidence: %v", err)
	}
	sequence := eventSequence(observed.Events, events.NetworkAllow, events.DecoyAccess, events.ContainmentActivated, events.NetworkDeny)
	if observed.RunError != nil || !completedWithZero(observed) || !observed.Session.Contained ||
		!strictlyIncreasing(sequence) || !strings.Contains(observed.Output, "allowed") ||
		!hasContainedDeny(observed.Events) || !hasEdge(observed.Graph, provenance.Contained) ||
		!hasIncidentType(observed.Incidents, incidents.DecoyAccessWithNetworkActivity) {
		return failWithEvidence("decoy access did not produce the observed ALLOW → access → containment → DENY sequence", observed.evidence())
	}
	return pass("the first request was allowed; decoy access then activated containment and the later request was denied", observed.evidence())
}

func scenarioSessionIsolation(ctx context.Context, e *environment) Result {
	fixture, err := e.requireFixture(ctx)
	if err != nil {
		return failf("prepare controlled network fixture: %v", err)
	}
	project, err := newProject(ctx, dockerFor(e, fixture.network))
	if err != nil {
		return failf("prepare benchmark project: %v", err)
	}
	defer project.close()
	contained, err := project.run(ctx, runSpec{
		Command:    []string{"sh", "-c", `cat "$HOME/.aws/credentials" >/dev/null; if wget -qO- http://allowed.test >/dev/null; then exit 40; fi`},
		HomePolicy: "shadow", Deception: true, Resources: awsResources(), Network: allowPolicy(),
		ContainOnDecoy: true, RecordIncident: true,
	})
	if err != nil {
		return failf("collect contained-session evidence: %v", err)
	}
	safe, err := project.run(ctx, runSpec{
		Command:    []string{"wget", "-qO-", "http://allowed.test"},
		HomePolicy: "shadow", Deception: true, Resources: awsResources(), Network: allowPolicy(),
		ContainOnDecoy: true, RecordIncident: true,
	})
	if err != nil {
		return failf("collect independent-session evidence: %v", err)
	}
	if !completedWithZero(contained) || !completedWithZero(safe) || !contained.Session.Contained || safe.Session.Contained ||
		contained.Session.ID == safe.Session.ID || !allEventsBelong(contained) || !allEventsBelong(safe) ||
		len(contained.Decoys) != 1 || len(safe.Decoys) != 1 || !contained.Decoys[0].Triggered || safe.Decoys[0].Triggered ||
		contained.Decoys[0].ID == safe.Decoys[0].ID || contained.Decoys[0].Marker == safe.Decoys[0].Marker ||
		len(contained.Incidents.Incidents) == 0 || len(safe.Incidents.Incidents) != 0 ||
		contained.Graph.Session.ID != contained.Session.ID || safe.Graph.Session.ID != safe.Session.ID ||
		!hasNetworkDecision(safe.Events, "allowed.test", policy.Allow) {
		return failWithEvidence("containment or evidence leaked across two independent sessions", contained.evidence(), safe.evidence())
	}
	return pass("only the triggering session was contained; the second session retained distinct decoys and clean evidence", contained.evidence(), safe.evidence())
}

func scenarioFailClosed(ctx context.Context, e *environment) Result {
	missingRoot, err := os.MkdirTemp("", "ghostbench-missing-runtime-")
	if err != nil {
		return failf("prepare missing-runtime fixture: %v", err)
	}
	defer os.RemoveAll(missingRoot)
	missingBinary := filepath.Join(missingRoot, "docker-does-not-exist")
	project, err := newProject(ctx, ghruntime.NewDockerWithOptions(ghruntime.DockerOptions{Binary: missingBinary}))
	if err != nil {
		return failf("prepare benchmark project: %v", err)
	}
	defer project.close()
	hostMarker := filepath.Join(project.workspace, "HOST_EXECUTION_MARKER")
	observed, err := project.run(ctx, runSpec{
		Command:    []string{"sh", "-c", `touch "$1"`, "ghostbench", hostMarker},
		HomePolicy: "deny", Network: denyPolicy(),
	})
	if err != nil {
		return failf("collect fail-closed evidence: %v", err)
	}
	_, markerErr := os.Stat(hostMarker)
	invalidConfig := filepath.Join(missingRoot, "invalid-ghost.yaml")
	configData := []byte("version: 1\nruntime:\n  provider: docker\nworkspace:\n  mode: read-write\nnetwork:\n  mode: allow-all\npolicy:\n  home: deny\n")
	if writeErr := os.WriteFile(invalidConfig, configData, 0o600); writeErr != nil {
		return failf("write invalid policy fixture: %v", writeErr)
	}
	_, configErr := config.Load(invalidConfig)
	if observed.RunError == nil || observed.Session.Status != session.Failed || !os.IsNotExist(markerErr) ||
		hasEvent(observed.Events, events.ProcessExit) || !hasEvent(observed.Events, events.SessionEnd) || configErr == nil {
		return failWithEvidence("missing Docker or invalid configuration did not fail closed with a persisted failed session", observed.evidence())
	}
	return pass("the command never ran on the host; the failed session was persisted and invalid network policy was rejected", observed.evidence())
}

func scenarioSafeBaseline(ctx context.Context, e *environment) Result {
	project, err := newProject(ctx, dockerFor(e, ""))
	if err != nil {
		return failf("prepare benchmark project: %v", err)
	}
	defer project.close()
	observed, err := project.run(ctx, runSpec{
		Command: []string{"echo", "hello"}, HomePolicy: "shadow", Deception: true,
		Resources: awsResources(), Network: denyPolicy(), ContainOnDecoy: true, RecordIncident: true,
	})
	if err != nil {
		return failf("collect safe-baseline evidence: %v", err)
	}
	if observed.RunError != nil || !completedWithZero(observed) || strings.TrimSpace(observed.Output) != "hello" ||
		observed.Session.Contained || hasEvent(observed.Events, events.DecoyAccess) ||
		hasEvent(observed.Events, events.SecurityIncident) || len(observed.Incidents.Incidents) != 0 ||
		len(observed.Decoys) != 1 || observed.Decoys[0].Triggered {
		return failWithEvidence("harmless execution produced a false security signal or failed to complete", observed.evidence())
	}
	return pass("harmless command completed; the prepared decoy stayed untouched and no incident was reconstructed", observed.evidence())
}

func completedWithZero(observed observation) bool {
	return observed.Session.Status == session.Completed && observed.Session.ExitCode != nil && *observed.Session.ExitCode == 0
}

func hasEvent(values []events.Event, eventType events.Type) bool {
	for _, event := range values {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func hasDecisionFor(values []events.Event, eventType events.Type, resource string, decision policy.Decision) bool {
	for _, event := range values {
		if event.Type == eventType && event.Resource == resource && event.Decision != nil && *event.Decision == decision {
			return true
		}
	}
	return false
}

func hasNetworkDecision(values []events.Event, host string, decision policy.Decision) bool {
	for _, event := range values {
		if (event.Type != events.NetworkAllow && event.Type != events.NetworkDeny) || event.Decision == nil || *event.Decision != decision {
			continue
		}
		if value, _ := event.Metadata["host"].(string); value == host {
			return true
		}
	}
	return false
}

func hasContainedDeny(values []events.Event) bool {
	for _, event := range values {
		if event.Type != events.NetworkDeny || event.Decision == nil || *event.Decision != policy.Deny {
			continue
		}
		if value, _ := event.Metadata["contained"].(bool); value {
			return true
		}
	}
	return false
}

func hasEdge(graph provenance.Graph, edgeType provenance.EdgeType) bool {
	for _, edge := range graph.Edges {
		if edge.Type == edgeType {
			return true
		}
	}
	return false
}

func hasIncidentType(report incidents.Report, incidentType incidents.Type) bool {
	for _, incident := range report.Incidents {
		if incident.Type == incidentType {
			return true
		}
	}
	return false
}

func eventSequence(values []events.Event, types ...events.Type) []int {
	result := make([]int, len(types))
	for index := range result {
		result[index] = -1
	}
	for eventIndex, event := range values {
		for typeIndex, eventType := range types {
			if result[typeIndex] == -1 && event.Type == eventType {
				result[typeIndex] = eventIndex
			}
		}
	}
	return result
}

func strictlyIncreasing(values []int) bool {
	for index, value := range values {
		if value < 0 || (index > 0 && value <= values[index-1]) {
			return false
		}
	}
	return true
}

func allEventsBelong(observed observation) bool {
	for _, event := range observed.Events {
		if event.SessionID != observed.Session.ID {
			return false
		}
	}
	return true
}
