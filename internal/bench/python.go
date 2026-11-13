package bench

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rappidAI-research/rappid-ghost/internal/compat"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
)

func scenarioPythonBoundaries(ctx context.Context, e *environment) Result {
	fixture, err := e.requireFixture(ctx)
	if err != nil {
		return failf("prepare controlled fixture: %v", err)
	}
	project, err := newProject(ctx, dockerFor(e, fixture.network))
	if err != nil {
		return failf("prepare Python project: %v", err)
	}
	defer project.close()
	script := fmt.Sprintf(`import os, socket, urllib.request
from pathlib import Path
assert os.getuid() != 0
assert not Path('/var/run/docker.sock').exists()
try:
    Path('/workspace/.ghost/ghost.db').open('rb')
except (FileNotFoundError, PermissionError):
    pass
else:
    raise AssertionError('Ghost database readable from guest')
assert urllib.request.urlopen('http://allowed.test',timeout=5).read() == b'allowed'
s = socket.socket(); s.settimeout(.3)
try:
    s.connect(('%s',80))
except OSError:
    pass
else:
    raise AssertionError('raw egress escaped gateway')
finally:
    s.close()
Path(os.environ['HOME'],'.aws','credentials').read_text()
try:
    urllib.request.urlopen('http://allowed.test',timeout=5)
except urllib.error.HTTPError as error:
    assert error.code == 403
else:
    raise AssertionError('SHADOW containment did not deny Python request')
`, fixture.ip)
	if err = os.WriteFile(filepath.Join(project.workspace, "agent.py"), []byte(script), 0600); err != nil {
		return failf("write Python fixture: %v", err)
	}
	command, err := compat.Prepare("python", "python", []string{"agent.py"})
	if err != nil {
		return failf("prepare Python adapter: %v", err)
	}
	observed, err := project.run(ctx, runSpec{Environment: "python", Command: command, HomePolicy: "shadow", Deception: true, Resources: awsResources(), Network: allowPolicy(), ContainOnDecoy: true, RecordIncident: true})
	if err != nil {
		return failf("collect Python observations: %v", err)
	}
	sequence := eventSequence(observed.Events, events.NetworkAllow, events.DecoyAccess, events.ContainmentActivated, events.NetworkDeny)
	if observed.RunError != nil || !completedWithZero(observed) || !observed.Session.IsContained() || !strictlyIncreasing(sequence) || !hasContainedDeny(observed.Events) || !fixture.healthy(ctx) {
		return failWithEvidence("Python agent failed confinement or ordered ALLOW -> SHADOW -> CONTAINED -> DENY validation", observed.evidence())
	}
	return pass("Python executed via the explicit adapter with non-root confinement, no raw egress and evidence-backed containment", observed.evidence())
}
