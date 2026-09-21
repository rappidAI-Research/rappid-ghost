package bench

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/events"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
)

func scenarioSessionTimeout(ctx context.Context, e *environment) Result {
	project, err := newProject(ctx, dockerFor(e, ""))
	if err != nil {
		return failf("prepare resource fixture: %v", err)
	}
	defer project.close()
	limits := ghruntime.DefaultLimits()
	limits.TimeoutSeconds, limits.GraceSeconds = 4, 1
	started := time.Now()
	observed, err := project.run(ctx, runSpec{Limits: &limits, Command: []string{"sh", "-c", `trap '' TERM; (trap '' TERM; while :; do date +%s%N > /workspace/heartbeat; sleep 0.05; done) & wait`}})
	if err != nil {
		return failf("collect timeout evidence: %v", err)
	}
	found := false
	for _, event := range observed.Events {
		if event.Type == events.ResourceLimitTriggered && event.Metadata["kind"] == ghruntime.ResourceTimeout && event.Metadata["classification"] == "operational" {
			found = true
		}
	}
	if observed.RunError == nil || observed.Session.Status != session.Failed || observed.Session.IsContained() || !found || len(observed.Incidents.Incidents) != 0 || time.Since(started) > 15*time.Second {
		return failWithEvidence("timeout failed to stop safely or invented a hostile incident", observed.evidence())
	}
	name := "ghost-agent-" + strings.ToLower(observed.Session.ID)
	output, inspectErr := exec.CommandContext(ctx, e.dockerBinary, "ps", "-aq", "--filter", "name=^/"+name+"$").CombinedOutput()
	if inspectErr != nil || strings.TrimSpace(string(output)) != "" {
		return failWithEvidence("timed-out container was not removed", observed.evidence())
	}
	before, err := os.ReadFile(filepath.Join(project.workspace, "heartbeat"))
	if err != nil {
		return failWithEvidence("descendant fixture never started", observed.evidence())
	}
	time.Sleep(150 * time.Millisecond)
	after, err := os.ReadFile(filepath.Join(project.workspace, "heartbeat"))
	if err != nil || string(before) != string(after) {
		return failWithEvidence("descendant survived cleanup", observed.evidence())
	}
	next, err := project.run(ctx, runSpec{Command: []string{"echo", "normal session after timeout"}})
	if err != nil || next.RunError != nil || !completedWithZero(next) || next.Session.IsContained() {
		return failWithEvidence("later session inherited failed runtime state", observed.evidence(), next.evidence())
	}
	for _, event := range next.Events {
		if event.Type == events.ResourceLimitTriggered {
			return failWithEvidence("resource evidence leaked across sessions", observed.evidence(), next.evidence())
		}
	}
	return pass("deadline removed the TERM-ignoring process tree; operational evidence remained session-local", observed.evidence(), next.evidence())
}
