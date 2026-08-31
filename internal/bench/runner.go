package bench

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type scenarioDefinition struct {
	ID              string
	Name            string
	Property        string
	RequiresDocker  bool
	RequiresFixture bool
	Run             func(context.Context, *environment) Result
}

type Runner struct {
	dockerBinary string
	dockerProbe  func(context.Context, string) error
}

func NewRunner() *Runner {
	return &Runner{dockerBinary: "docker", dockerProbe: probeDocker}
}

func ScenarioIDs() []string {
	definitions := scenarioDefinitions()
	result := make([]string, len(definitions))
	for index, definition := range definitions {
		result[index] = definition.ID
	}
	return result
}

func ValidateOptions(options Options) error {
	if options.Scenario == "" {
		return nil
	}
	for _, id := range ScenarioIDs() {
		if options.Scenario == id {
			return nil
		}
	}
	return fmt.Errorf("unknown benchmark scenario %q", options.Scenario)
}

func (r *Runner) Run(ctx context.Context, options Options) Report {
	if err := ValidateOptions(options); err != nil {
		return newReport([]Result{{
			Scenario: options.Scenario, Name: "Unknown scenario",
			Property: "Only registered benchmark scenarios may run.", Status: Fail,
			Detail: err.Error(), Evidence: []EvidenceBundle{},
		}})
	}
	definitions := scenarioDefinitions()
	if options.Scenario != "" {
		selected := definitions[:0]
		for _, definition := range definitions {
			if definition.ID == options.Scenario {
				selected = append(selected, definition)
			}
		}
		definitions = selected
	}

	environment := &environment{dockerBinary: r.dockerBinary}
	needsDocker := false
	for _, definition := range definitions {
		needsDocker = needsDocker || definition.RequiresDocker
	}
	if needsDocker {
		if err := r.dockerProbe(ctx, r.dockerBinary); err != nil {
			environment.dockerUnavailable = err.Error()
		}
	}

	results := make([]Result, 0, len(definitions))
	for _, definition := range definitions {
		if definition.RequiresDocker && environment.dockerUnavailable != "" {
			results = append(results, Result{
				Scenario: definition.ID, Name: definition.Name, Property: definition.Property,
				Status: Skip, Detail: environment.dockerUnavailable, Evidence: []EvidenceBundle{},
			})
			continue
		}
		scenarioCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		result := definition.Run(scenarioCtx, environment)
		cancel()
		result.Scenario = definition.ID
		result.Name = definition.Name
		result.Property = definition.Property
		if result.Status != Pass && result.Status != Fail && result.Status != Skip {
			result.Status = Fail
			result.Detail = "scenario returned an invalid result status"
			result.Evidence = nil
		}
		results = append(results, result)
	}
	if cleanupErr := environment.close(); cleanupErr != nil {
		fixtureScenarios := make(map[string]bool)
		for _, definition := range definitions {
			if definition.RequiresFixture {
				fixtureScenarios[definition.ID] = true
			}
		}
		for index := range results {
			if fixtureScenarios[results[index].Scenario] && results[index].Status == Pass {
				results[index].Status = Fail
				results[index].Detail += "; controlled fixture cleanup failed: " + cleanupErr.Error()
			}
		}
	}
	return newReport(results)
}

func probeDocker(ctx context.Context, binary string) error {
	if _, err := exec.LookPath(binary); err != nil {
		return errors.New("Docker CLI unavailable; scenario was not executed")
	}
	command := exec.CommandContext(ctx, binary, "info", "--format", "{{.ServerVersion}}")
	output, err := command.CombinedOutput()
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(output))
	if lines := strings.Split(message, "\n"); len(lines) > 0 {
		message = strings.TrimSpace(lines[len(lines)-1])
	}
	if message == "" {
		message = err.Error()
	}
	return fmt.Errorf("Docker daemon unavailable; scenario was not executed: %s", message)
}

func pass(detail string, evidence ...EvidenceBundle) Result {
	return Result{Status: Pass, Detail: detail, Evidence: evidence}
}

func failf(format string, arguments ...any) Result {
	return Result{Status: Fail, Detail: fmt.Sprintf(format, arguments...), Evidence: []EvidenceBundle{}}
}

func failWithEvidence(detail string, evidence ...EvidenceBundle) Result {
	return Result{Status: Fail, Detail: detail, Evidence: evidence}
}
