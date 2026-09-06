package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type dockerResource struct {
	id        string
	name      string
	component string
}

// Recover removes only resources that carry the expected Ghost session and
// component labels and whose names exactly match that session. Any ambiguity
// aborts recovery before Ghost starts another untrusted command.
func (d *DockerRuntime) Recover(ctx context.Context, sessionIDs []string) error {
	if len(sessionIDs) == 0 {
		return nil
	}
	if err := d.available(ctx); err != nil {
		return err
	}
	for _, sessionID := range sessionIDs {
		if !safeContainerComponent.MatchString(sessionID) {
			return fmt.Errorf("invalid interrupted session identity %q", sessionID)
		}
		containers, err := d.ownedContainers(ctx, sessionID)
		if err != nil {
			return err
		}
		for _, resource := range containers {
			if output, err := dockerCleanup(d.binary, "rm", "--force", resource.id); err != nil && !dockerObjectMissing(output) {
				return fmt.Errorf("remove stale Ghost %s container %s: %s", resource.component, resource.name, lastMessage(string(output)))
			}
		}

		networks, err := d.ownedNetworks(ctx, sessionID)
		if err != nil {
			return err
		}
		for _, resource := range networks {
			if output, err := dockerCleanup(d.binary, "network", "rm", resource.id); err != nil && !dockerObjectMissing(output) {
				return fmt.Errorf("remove stale Ghost network %s: %s", resource.name, lastMessage(string(output)))
			}
		}
	}
	return nil
}

func (d *DockerRuntime) ownedContainers(ctx context.Context, sessionID string) ([]dockerResource, error) {
	ids, err := d.listDockerIDs(ctx, "ps", "-aq", "--filter", "label=ghost.session="+sessionID)
	if err != nil {
		return nil, fmt.Errorf("list stale Ghost containers: %w", err)
	}
	resources := make([]dockerResource, 0, len(ids))
	for _, id := range ids {
		labels, name, missing, err := d.inspectContainer(ctx, id)
		if err != nil {
			return nil, err
		}
		if missing {
			continue
		}
		component := labels["ghost.component"]
		if labels["ghost.session"] != sessionID || !validContainerOwnership(sessionID, component, name) {
			return nil, fmt.Errorf("refusing cleanup of ambiguously owned container %s", id)
		}
		resources = append(resources, dockerResource{id: id, name: name, component: component})
	}
	return resources, nil
}

func (d *DockerRuntime) ownedNetworks(ctx context.Context, sessionID string) ([]dockerResource, error) {
	ids, err := d.listDockerIDs(ctx, "network", "ls", "-q", "--filter", "label=ghost.session="+sessionID)
	if err != nil {
		return nil, fmt.Errorf("list stale Ghost networks: %w", err)
	}
	resources := make([]dockerResource, 0, len(ids))
	for _, id := range ids {
		labels, name, missing, err := d.inspectNetwork(ctx, id)
		if err != nil {
			return nil, err
		}
		if missing {
			continue
		}
		component := labels["ghost.component"]
		if labels["ghost.session"] != sessionID || component != "network" || !validNetworkOwnership(sessionID, name) {
			return nil, fmt.Errorf("refusing cleanup of ambiguously owned network %s", id)
		}
		resources = append(resources, dockerResource{id: id, name: name, component: component})
	}
	return resources, nil
}

func (d *DockerRuntime) listDockerIDs(ctx context.Context, arguments ...string) ([]string, error) {
	output, err := exec.CommandContext(ctx, d.binary, arguments...).CombinedOutput()
	if err != nil {
		message := lastMessage(string(output))
		if message == "" {
			message = err.Error()
		}
		return nil, errors.New(message)
	}
	return strings.Fields(string(output)), nil
}

func (d *DockerRuntime) inspectContainer(ctx context.Context, id string) (map[string]string, string, bool, error) {
	labels, missing, err := d.inspectLabels(ctx, id)
	if err != nil || missing {
		return nil, "", missing, err
	}
	output, err := exec.CommandContext(ctx, d.binary, "inspect", "--format", "{{.Name}}", id).CombinedOutput()
	if err != nil {
		if dockerObjectMissing(output) {
			return nil, "", true, nil
		}
		return nil, "", false, fmt.Errorf("inspect stale Ghost container name: %s", lastMessage(string(output)))
	}
	return labels, strings.TrimPrefix(strings.TrimSpace(string(output)), "/"), false, nil
}

func (d *DockerRuntime) inspectNetwork(ctx context.Context, id string) (map[string]string, string, bool, error) {
	output, err := exec.CommandContext(ctx, d.binary, "network", "inspect", "--format", "{{json .Labels}}", id).CombinedOutput()
	if err != nil {
		if dockerObjectMissing(output) {
			return nil, "", true, nil
		}
		return nil, "", false, fmt.Errorf("inspect stale Ghost network labels: %s", lastMessage(string(output)))
	}
	labels := map[string]string{}
	if err := json.Unmarshal(output, &labels); err != nil {
		return nil, "", false, fmt.Errorf("decode stale Ghost network labels: %w", err)
	}
	output, err = exec.CommandContext(ctx, d.binary, "network", "inspect", "--format", "{{.Name}}", id).CombinedOutput()
	if err != nil {
		if dockerObjectMissing(output) {
			return nil, "", true, nil
		}
		return nil, "", false, fmt.Errorf("inspect stale Ghost network name: %s", lastMessage(string(output)))
	}
	return labels, strings.TrimSpace(string(output)), false, nil
}

func (d *DockerRuntime) inspectLabels(ctx context.Context, id string) (map[string]string, bool, error) {
	output, err := exec.CommandContext(ctx, d.binary, "inspect", "--format", "{{json .Config.Labels}}", id).CombinedOutput()
	if err != nil {
		if dockerObjectMissing(output) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("inspect stale Ghost container labels: %s", lastMessage(string(output)))
	}
	labels := map[string]string{}
	if err := json.Unmarshal(output, &labels); err != nil {
		return nil, false, fmt.Errorf("decode stale Ghost container labels: %w", err)
	}
	return labels, false, nil
}

func validContainerOwnership(sessionID, component, name string) bool {
	suffix := strings.ToLower(sessionID)
	expected := map[string]string{
		"agent":    "ghost-agent-" + suffix,
		"sentinel": "ghost-sentinel-" + suffix,
		"gateway":  "ghost-gateway-" + suffix,
	}
	return expected[component] != "" && name == expected[component]
}

func validNetworkOwnership(sessionID, name string) bool {
	suffix := strings.ToLower(sessionID)
	return name == "ghost-agent-"+suffix || name == "ghost-egress-"+suffix
}

func dockerObjectMissing(output []byte) bool {
	message := strings.ToLower(string(output))
	return strings.Contains(message, "no such container") ||
		strings.Contains(message, "no such object") ||
		strings.Contains(message, "not found")
}

var _ Recoverer = (*DockerRuntime)(nil)
