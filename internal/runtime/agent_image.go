package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rappidAI-research/rappid-ghost/internal/compat"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	goruntime "runtime"
	"strings"
	"time"
)

var imageIDPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// The catalog controls supply-chain identity. Inspect also refuses image-side
// behavior that could create writable anonymous volumes or extra processes.
// Return the immutable local content ID for the actual container creation.
func (d *DockerRuntime) validateAgentImage(ctx context.Context, image string) (string, error) {
	return d.validateImageMetadata(ctx, image, nil)
}
func (d *DockerRuntime) validateImageMetadata(ctx context.Context, image string, entrypoint []string) (string, error) {
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
	if !imageIDPattern.MatchString(info.ID) || info.OS != "linux" || len(info.Config.Volumes) != 0 || (len(info.Config.Entrypoint) > 0 && !reflect.DeepEqual(info.Config.Entrypoint, entrypoint)) || len(info.Config.OnBuild) != 0 || info.Config.Healthcheck != nil {
		return "", errors.New("catalog agent image must be Linux with an immutable ID and no volumes, entrypoint, healthcheck or on-build hooks")
	}
	return info.ID, nil
}

// prepareDerivedImage uses only source-reviewed bytes on stdin; no workspace
// is a build context. BuildKit is required, and RUN has no network route.
func (d *DockerRuntime) prepareDerivedImage(ctx context.Context, environment compat.Environment) (string, error) {
	if environment.Architecture != "" && environment.Architecture != goruntime.GOARCH {
		return "", fmt.Errorf("runtime %s is qualified only for %s; no architecture fallback", environment.Name, environment.Architecture)
	}
	source := *d
	source.image = environment.Image
	if err := source.ensureImage(ctx); err != nil {
		return "", err
	}
	// Refuse source image hooks/volumes before even the fixed build recipe runs.
	if _, err := d.validateImageMetadata(ctx, environment.Image, environment.SourceEntrypoint); err != nil {
		return "", err
	}
	buildCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(buildCtx, d.binary, "build", "--quiet", "--network", "none", "--build-arg", "SOURCE_DATE_EPOCH=0", "-")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "DOCKER_BUILDKIT=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "DOCKER_BUILDKIT=1")
	cmd.Stdin = strings.NewReader(environment.BuildRecipe)
	cmd.WaitDelay = time.Second
	var output oomOutput
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("build reviewed agent image (Docker BuildKit required, no host fallback): %w", err)
	}
	id := strings.TrimSpace(string(output.Bytes()))
	if !imageIDPattern.MatchString(id) {
		return "", errors.New("Docker build returned an invalid image identity")
	}
	validated, err := d.validateAgentImage(ctx, id)
	if err != nil {
		return "", err
	}
	if validated != id {
		return "", errors.New("built image identity changed before validation")
	}
	return id, nil
}

// PreparedCatalogImages prepares exactly the same final images used by the
// runtime so CI scans the shipped filesystem, including reviewed removals.
func PreparedCatalogImages(ctx context.Context) ([]string, error) {
	d := NewDocker()
	images := []string{DefaultDockerImage}
	for _, name := range []string{"python", "node", "codex"} {
		environment, err := compat.ResolveEnvironment(name)
		if err != nil {
			return nil, err
		}
		if environment.Architecture != "" && environment.Architecture != goruntime.GOARCH {
			continue
		}
		id, err := d.prepareDerivedImage(ctx, environment)
		if err != nil {
			return nil, err
		}
		images = append(images, id)
	}
	return images, nil
}
