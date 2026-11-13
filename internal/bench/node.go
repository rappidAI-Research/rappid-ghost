package bench

import (
	"context"
	"github.com/rappidAI-research/rappid-ghost/internal/compat"
	"os"
	"path/filepath"
)

func scenarioNodeBoundaries(ctx context.Context, e *environment) Result {
	project, err := newProject(ctx, dockerFor(e, ""))
	if err != nil {
		return failf("prepare Node project: %v", err)
	}
	defer project.close()
	script := `const fs=require('node:fs');const assert=require('node:assert/strict');const net=require('node:net');
assert.notEqual(process.getuid(),0);assert.throws(()=>fs.writeFileSync('/usr/local/escape','bad'));assert.throws(()=>fs.readFileSync('/workspace/.ghost/ghost.db'));
assert.throws(()=>fs.accessSync('/var/run/docker.sock'));assert.throws(()=>fs.accessSync('/usr/local/bin/npm'));
const socket=net.connect({host:'1.1.1.1',port:443});socket.setTimeout(300);
socket.once('connect',()=>{throw Error('raw egress bypass')});socket.once('timeout',()=>socket.destroy(Error('denied')));
socket.once('error',()=>{fs.writeFileSync('node-proof.txt','NODE_BOUNDARIES_OK');console.log('NODE_BOUNDARIES_OK')});`
	if err = os.WriteFile(filepath.Join(project.workspace, "agent.cjs"), []byte(script), 0600); err != nil {
		return failf("write Node fixture: %v", err)
	}
	command, err := compat.Prepare("node", "node", []string{"agent.cjs"})
	if err != nil {
		return failf("prepare Node adapter: %v", err)
	}
	observed, err := project.run(ctx, runSpec{Environment: "node", Command: command, HomePolicy: "deny", Network: denyPolicy()})
	if err != nil {
		return failf("collect Node evidence: %v", err)
	}
	proof, readErr := os.ReadFile(filepath.Join(project.workspace, "node-proof.txt"))
	if observed.RunError != nil || !completedWithZero(observed) || readErr != nil || string(proof) != "NODE_BOUNDARIES_OK" {
		return failWithEvidence("Node confinement, module or network assertion failed", observed.evidence())
	}
	return pass("Node built-in modules executed within non-root, read-only-root, private-state and raw-egress boundaries", observed.evidence())
}
