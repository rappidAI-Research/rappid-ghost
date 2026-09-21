package runtime

import (
	"context"
	"os"
	"testing"

	"github.com/rappidAI-research/rappid-ghost/internal/policy"
)

func TestFinalizationRetainsContainmentWhenEvidenceCannotBeCollected(t *testing.T) {
	for _, kind := range []string{"malformed", "oversized", "ambiguous-marker"} {
		t.Run(kind, func(t *testing.T) {
			request := RunRequest{SessionID: "finalization", SessionDir: t.TempDir(), Command: []string{"true"}}
			observation, err := prepareObservation(request)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(observation.contained, nil, 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "malformed":
				err = os.WriteFile(observation.events, []byte("not-json\n"), 0600)
			case "oversized":
				err = os.Truncate(observation.events, 16*1024*1024+1)
			case "ambiguous-marker":
				err = os.WriteFile(observation.contained, []byte("invalid"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			d := NewDockerWithOptions(DockerOptions{Binary: controlledDocker(t, "exit 0", "")})
			result, err := d.runPrepared(context.Background(), request, t.TempDir(), t.TempDir(), observation, "1000:1000")
			if err == nil || !result.Started {
				t.Fatalf("expected post-launch evidence failure: %+v, %v", result, err)
			}
			if kind != "ambiguous-marker" && result.SecurityState != policy.StateContained {
				t.Fatalf("lost authoritative containment on %s evidence: %+v, %v", kind, result, err)
			}
			if kind == "ambiguous-marker" && result.SecurityState == policy.StateContained {
				t.Fatal("ambiguous marker invented containment")
			}
			if len(result.Accesses) != 0 {
				t.Fatal("invented decoy access from marker alone")
			}
			if _, err := os.Lstat(observation.events); err != nil {
				t.Fatal("original evidence was removed", err)
			}
		})
	}
}
