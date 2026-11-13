package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"time"
)

var imageIDPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// The catalog controls supply-chain identity. Inspect also refuses image-side
// behavior that could create writable anonymous volumes or extra processes.
// Return the immutable local content ID for the actual container creation.
func (d *DockerRuntime) validateAgentImage(ctx context.Context, image string) (string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(probeCtx, d.binary, "image", "inspect", "--format", "{{json .}}", image)
	var output oomOutput
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("inspect catalog agent image: %w", err)
	}
	var info struct {
		ID     string `json:"Id"`
		OS     string `json:"Os"`
		Config struct {
			Volumes     map[string]json.RawMessage
			Entrypoint  []string
			OnBuild     []string
			Healthcheck *json.RawMessage
		}
	}
	if err := json.Unmarshal(output.Bytes(), &info); err != nil {
		return "", errors.New("invalid agent image metadata")
	}
	if !imageIDPattern.MatchString(info.ID) || info.OS != "linux" || len(info.Config.Volumes) != 0 || len(info.Config.Entrypoint) != 0 || len(info.Config.OnBuild) != 0 || info.Config.Healthcheck != nil {
		return "", errors.New("catalog agent image must be Linux with an immutable ID and no volumes, entrypoint, healthcheck or on-build hooks")
	}
	return info.ID, nil
}
