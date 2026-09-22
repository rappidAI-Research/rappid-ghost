package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/approval"
	"github.com/rappidAI-research/rappid-ghost/internal/bench"
	"github.com/rappidAI-research/rappid-ghost/internal/config"
	"github.com/rappidAI-research/rappid-ghost/internal/deception"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	ghostincidents "github.com/rappidAI-research/rappid-ghost/internal/incidents"
	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
	"github.com/rappidAI-research/rappid-ghost/internal/provenance"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
	"github.com/rappidAI-research/rappid-ghost/internal/storage"
)

// Version is overridden with -ldflags for tagged release artifacts.
var Version = "0.3.1-dev"

func Execute(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printHelp(stdout)
		return 0
	}

	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "ghost: determine current directory: %v\n", err)
		return 1
	}

	switch args[0] {
	case "init":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "ghost: usage: ghost init")
			return 2
		}
		if err := initProject(ctx, root, stdout); err != nil {
			fmt.Fprintf(stderr, "ghost: %v\n", err)
			return 1
		}
		return 0
	case "run":
		if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
			fmt.Fprintln(stdout, "Usage: ghost run [--] <command> [arguments...]")
			return 0
		}
		command, err := parseRunArgs(args[1:])
		if err != nil {
			fmt.Fprintf(stderr, "ghost: %v\n", err)
			return 2
		}
		return runCommand(ctx, root, command, stdin, stdout, stderr)
	case "inspect":
		selector, err := parseInspectArgs(args[1:])
		if err != nil {
			fmt.Fprintf(stderr, "ghost: %v\n", err)
			return 2
		}
		if err := inspectSession(ctx, root, selector, stdout); err != nil {
			fmt.Fprintf(stderr, "ghost: %v\n", err)
			return 1
		}
		return 0
	case "graph":
		selector, jsonOutput, err := parseGraphArgs(args[1:])
		if err != nil {
			fmt.Fprintf(stderr, "ghost: %v\n", err)
			return 2
		}
		if err := graphSession(ctx, root, selector, jsonOutput, stdout); err != nil {
			fmt.Fprintf(stderr, "ghost: %v\n", err)
			return 1
		}
		return 0
	case "incidents":
		selector, jsonOutput, err := parseIncidentsArgs(args[1:])
		if err != nil {
			fmt.Fprintf(stderr, "ghost: %v\n", err)
			return 2
		}
		if err := incidentsSession(ctx, root, selector, jsonOutput, stdout); err != nil {
			fmt.Fprintf(stderr, "ghost: %v\n", err)
			return 1
		}
		return 0
	case "bench":
		if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
			fmt.Fprintln(stdout, "Usage: ghost bench [--json] [--require-all] [--scenario <name>]")
			fmt.Fprintln(stdout, "Run 'ghost bench --json' for versioned machine-readable results.")
			fmt.Fprintln(stdout, "--require-all returns non-zero when any scenario is FAIL or SKIP.")
			return 0
		}
		options, jsonOutput, err := parseBenchArgs(args[1:])
		if err != nil {
			fmt.Fprintf(stderr, "ghost: %v\n", err)
			return 2
		}
		report := bench.NewRunner().Run(ctx, options)
		if jsonOutput {
			if err := bench.WriteJSON(stdout, report); err != nil {
				fmt.Fprintf(stderr, "ghost: write benchmark JSON: %v\n", err)
				return 1
			}
		} else {
			bench.WriteText(stdout, report)
		}
		if !report.Successful() || (options.RequireAll && !report.Complete()) {
			return 1
		}
		return 0
	case "version", "--version", "-v":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "ghost: usage: ghost version")
			return 2
		}
		fmt.Fprintf(stdout, "ghost %s\n", Version)
		return 0
	default:
		fmt.Fprintf(stderr, "ghost: unknown command %q\n", args[0])
		if suggestion := commandSuggestion(args[0]); suggestion != "" {
			fmt.Fprintf(stderr, "Did you mean 'ghost %s'?\n", suggestion)
		} else {
			fmt.Fprintln(stderr, "Run 'ghost --help' for usage.")
		}
		return 2
	}
}

func initProject(ctx context.Context, root string, output io.Writer) error {
	configPath := filepath.Join(root, config.FileName)
	created, err := config.WriteDefault(configPath)
	if err != nil {
		return err
	}
	if _, err := config.Load(configPath); err != nil {
		return err
	}

	store, err := prepareProjectState(ctx, root)
	if err != nil {
		return err
	}
	if err := store.Close(); err != nil {
		return fmt.Errorf("close Ghost database: %w", err)
	}
	gitIgnoreErr := ensureGitIgnoreEntry(root)

	if created {
		fmt.Fprintln(output, "Ghost initialized.")
		fmt.Fprintln(output, "  Config: ghost.yaml")
		fmt.Fprintln(output, "  Data:   .ghost/")
		fmt.Fprintln(output, "  Next:   ghost run <agent>")
	} else {
		fmt.Fprintln(output, "Ghost already initialized; existing ghost.yaml preserved.")
		fmt.Fprintln(output, "  Run: ghost run <agent>")
	}
	if gitIgnoreErr != nil {
		fmt.Fprintf(output, "  Note: add .ghost/ to .gitignore manually (%v).\n", gitIgnoreErr)
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return os.Mkdir(path, 0o700)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to use a symlink")
	}
	if !info.IsDir() {
		return errors.New("path exists but is not a directory")
	}
	return os.Chmod(path, 0o700)
}

func prepareProjectState(ctx context.Context, root string) (*storage.Store, error) {
	runtimeDir := filepath.Join(root, config.RuntimeDirName)
	if err := ensurePrivateDirectory(runtimeDir); err != nil {
		return nil, fmt.Errorf("prepare Ghost runtime directory: %w", err)
	}
	if err := ensurePrivateDirectory(filepath.Join(runtimeDir, config.SessionsDir)); err != nil {
		return nil, fmt.Errorf("prepare Ghost sessions directory: %w", err)
	}
	store, err := storage.Open(ctx, filepath.Join(runtimeDir, config.DatabaseName))
	if err != nil {
		return nil, fmt.Errorf("prepare Ghost database: %w", err)
	}
	return store, nil
}

func ensureGitIgnoreEntry(root string) error {
	gitPath := filepath.Join(root, ".git")
	gitInfo, err := os.Lstat(gitPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect .git: %w", err)
	}
	if gitInfo.Mode()&os.ModeSymlink != 0 || (!gitInfo.IsDir() && !gitInfo.Mode().IsRegular()) {
		return errors.New(".git must be a directory or regular worktree file")
	}

	ignorePath := filepath.Join(root, ".gitignore")
	var existing []byte
	if info, statErr := os.Lstat(ignorePath); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New(".gitignore must be a regular file, not a symlink")
		}
		if info.Size() > 1024*1024 {
			return errors.New(".gitignore is too large to update safely; add .ghost/ manually")
		}
		existing, err = os.ReadFile(ignorePath)
		if err != nil {
			return fmt.Errorf("read .gitignore: %w", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect .gitignore: %w", statErr)
	}
	for _, line := range strings.Split(string(existing), "\n") {
		switch strings.TrimSpace(line) {
		case ".ghost", ".ghost/", "/.ghost", "/.ghost/":
			return nil
		}
	}

	file, err := os.OpenFile(ignorePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return fmt.Errorf("open .gitignore: %w", err)
	}
	entry := []byte(".ghost/\n")
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		entry = append([]byte("\n"), entry...)
	}
	_, writeErr := file.Write(entry)
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("update .gitignore: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close .gitignore: %w", closeErr)
	}
	return nil
}

func parseRunArgs(args []string) ([]string, error) {
	if len(args) == 0 {
		return nil, errors.New("usage: ghost run [--] <command> [arguments...]")
	}
	if args[0] == "--" {
		if len(args) == 1 {
			return nil, errors.New("usage: ghost run [--] <command> [arguments...]")
		}
		return append([]string(nil), args[1:]...), nil
	}
	if strings.HasPrefix(args[0], "-") {
		return nil, errors.New("a command beginning with '-' must follow '--': ghost run -- <command>")
	}
	return append([]string(nil), args...), nil
}

func parseInspectArgs(args []string) (string, error) {
	if len(args) == 0 {
		return "latest", nil
	}
	if len(args) == 1 && validSelector(args[0]) {
		return args[0], nil
	}
	return "", errors.New("usage: ghost inspect [session-id|latest]")
}

func parseGraphArgs(args []string) (string, bool, error) {
	return parseReportArgs("graph", args)
}

func parseIncidentsArgs(args []string) (string, bool, error) {
	return parseReportArgs("incidents", args)
}

func parseBenchArgs(args []string) (bench.Options, bool, error) {
	var options bench.Options
	jsonOutput := false
	for index := 0; index < len(args); index++ {
		switch argument := args[index]; {
		case argument == "--json":
			if jsonOutput {
				return bench.Options{}, false, errors.New("usage: ghost bench [--json] [--require-all] [--scenario <name>]")
			}
			jsonOutput = true
		case argument == "--require-all":
			if options.RequireAll {
				return bench.Options{}, false, errors.New("usage: ghost bench [--json] [--require-all] [--scenario <name>]")
			}
			options.RequireAll = true
		case argument == "--scenario":
			if options.Scenario != "" || index+1 >= len(args) {
				return bench.Options{}, false, errors.New("usage: ghost bench [--json] [--require-all] [--scenario <name>]")
			}
			index++
			options.Scenario = args[index]
		case strings.HasPrefix(argument, "--scenario="):
			if options.Scenario != "" {
				return bench.Options{}, false, errors.New("usage: ghost bench [--json] [--require-all] [--scenario <name>]")
			}
			options.Scenario = strings.TrimPrefix(argument, "--scenario=")
		default:
			return bench.Options{}, false, errors.New("usage: ghost bench [--json] [--require-all] [--scenario <name>]")
		}
	}
	if err := bench.ValidateOptions(options); err != nil {
		return bench.Options{}, false, fmt.Errorf("%w; available scenarios: %s", err, strings.Join(bench.ScenarioIDs(), ", "))
	}
	return options, jsonOutput, nil
}

func parseReportArgs(command string, args []string) (string, bool, error) {
	if len(args) == 0 {
		return "latest", false, nil
	}
	if len(args) == 1 && args[0] == "--json" {
		return "latest", true, nil
	}
	if len(args) == 1 && validSelector(args[0]) {
		return args[0], false, nil
	}
	if len(args) == 2 && validSelector(args[0]) && args[1] == "--json" {
		return args[0], true, nil
	}
	return "", false, fmt.Errorf("usage: ghost %s [session-id|latest] [--json]", command)
}

func commandSuggestion(value string) string {
	known := []string{"init", "run", "inspect", "graph", "incidents", "bench", "version", "help"}
	best, distance := "", 3
	for _, candidate := range known {
		current := editDistance(strings.ToLower(value), candidate)
		if current < distance {
			best, distance = candidate, current
		}
	}
	if distance == 1 || (distance == 2 && len(value) >= 5) {
		return best
	}
	return ""
}

func editDistance(left, right string) int {
	previous := make([]int, len(right)+1)
	for index := range previous {
		previous[index] = index
	}
	for leftIndex := 1; leftIndex <= len(left); leftIndex++ {
		current := make([]int, len(right)+1)
		current[0] = leftIndex
		for rightIndex := 1; rightIndex <= len(right); rightIndex++ {
			cost := 0
			if left[leftIndex-1] != right[rightIndex-1] {
				cost = 1
			}
			current[rightIndex] = min(current[rightIndex-1]+1, previous[rightIndex]+1, previous[rightIndex-1]+cost)
		}
		previous = current
	}
	return previous[len(right)]
}

func validSelector(value string) bool {
	return value != "" && !strings.HasPrefix(value, "-")
}

type runtimeFactory func(provider string) (ghruntime.Runtime, error)

func newConfiguredRuntime(provider string) (ghruntime.Runtime, error) {
	switch provider {
	case "docker":
		return ghruntime.NewDocker(), nil
	default:
		return nil, fmt.Errorf("unsupported runtime provider %q", provider)
	}
}

func runCommand(ctx context.Context, root string, command []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runCommandWithFactory(ctx, root, command, stdin, stdout, stderr, newConfiguredRuntime)
}

func runCommandWithFactory(ctx context.Context, root string, command []string, stdin io.Reader, stdout, stderr io.Writer, factory runtimeFactory) int {
	cfg, err := config.Load(filepath.Join(root, config.FileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeSetupFailure(stderr, "Ghost project is not initialized.", "Run 'ghost init' in this workspace.", nil, "")
		} else {
			writeSetupFailure(stderr, "Project configuration is invalid.", "Correct ghost.yaml before running the agent.", err, "")
		}
		return 1
	}
	runtimeDir := filepath.Join(root, config.RuntimeDirName)
	store, err := prepareProjectState(ctx, root)
	if err != nil {
		writeSetupFailure(stderr, "Ghost could not prepare its private project state.", "The agent was not launched. Fix the reported .ghost path or permissions, then rerun the command.", err, "")
		return 1
	}
	defer store.Close()

	if factory == nil {
		writeSetupFailure(stderr, "Ghost runtime setup is unavailable.", "The agent was not launched.", errors.New("runtime factory is nil"), "")
		return 1
	}
	runner, err := factory(cfg.Runtime.Provider)
	if err != nil {
		writeSetupFailure(stderr, "The configured runtime is not supported.", "The agent was not launched.", err, "")
		return 1
	}
	manager := session.NewManager(store, runner)
	networkPolicy, err := ghostnetwork.NewPolicyWithApproval(cfg.Network.Mode, cfg.Network.Allow, cfg.Network.Ask)
	if err != nil {
		writeSetupFailure(stderr, "Network policy is invalid.", "The agent was not launched.", err, "")
		return 1
	}
	agentInput := stdin
	var approvalHandler approval.Handler
	if len(networkPolicy.Ask) > 0 && approval.InteractiveAvailable(stdin, stderr) {
		terminalMux := approval.NewTerminalMux(stdin, stderr)
		approvalHandler = terminalMux
		agentInput = terminalMux.AgentInput()
		defer terminalMux.Close()
	}
	value, runErr := manager.Run(ctx, session.RunRequest{
		Runtime: ghruntime.RunRequest{
			Limits:  &cfg.Runtime.Limits,
			Command: command, Workspace: root,
			WorkspaceReadOnly: cfg.Workspace.Mode == "read-only",
			Stdin:             agentInput, Stdout: stdout, Stderr: stderr,
			ApprovalHandler: approvalHandler,
		},
		SessionsDir:      filepath.Join(runtimeDir, config.SessionsDir),
		HomePolicy:       cfg.Policy.Home,
		DeceptionEnabled: cfg.Deception.Enabled,
		Resources: session.ResourcePolicy{
			AWSCredentials: cfg.Deception.Resources.AWSCredentials,
			SSHPrivateKey:  cfg.Deception.Resources.SSHPrivateKey,
			EnvFile:        cfg.Deception.Resources.EnvFile,
		},
		IncidentSeverity: cfg.OnDecoyAccess.Severity,
		RecordIncident:   cfg.OnDecoyAccess.RecordIncident,
		NetworkPolicy:    networkPolicy,
		ContainOnDecoy:   cfg.OnDecoyAccess.Network == "deny",
		SecurityNotice: func(notice session.SecurityNotice) {
			if notice.Type == events.PromptInjectionSuspected && notice.Sources > 0 {
				fmt.Fprintf(stderr, "Ghost detected suspicious instructions in %d workspace source(s). Protection remains active.\n", notice.Sources)
			}
		},
	})
	if runErr != nil {
		writeRunFailure(stderr, value, runErr)
		// Runtime failures still have durable evidence worth summarizing. The
		// execution context may have been cancelled by the user or a limit.
		summaryCtx, cancelSummary := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancelSummary()
		if storedEvents, err := store.Events(summaryCtx, value.ID); err == nil && summarizeSecurity(value, storedEvents).relevant() {
			writeRunSummary(stdout, value, storedEvents)
		}
		return 1
	}
	if value.ExitCode == nil {
		writeSetupFailure(stderr, "Ghost could not verify the isolated command's exit status.", "The session failed closed.", nil, value.ID)
		return 1
	}
	if *value.ExitCode == 0 {
		fmt.Fprintln(stdout, "Ghost completed successfully.")
	} else {
		fmt.Fprintf(stdout, "Ghost command exited with code %d.\n", *value.ExitCode)
	}
	storedEvents, eventErr := store.Events(ctx, value.ID)
	if eventErr != nil {
		fmt.Fprintln(stderr, "Ghost completed the runtime session but could not reconstruct its security summary.")
		fmt.Fprintln(stderr, "The recorded session remains available for inspection.")
		fmt.Fprintf(stderr, "Details: %v\nSession: %s\n", eventErr, value.ID)
		return 1
	}
	writeRunSummary(stdout, value, storedEvents)
	if *value.ExitCode != 0 {
		if cfg.Network.Mode == string(ghostnetwork.Deny) && mayRequireNetwork(command) {
			fmt.Fprintln(stderr, "Hint: This project blocks network access. If the command needed it, configure an exact allowlist in ghost.yaml; Ghost will not enable networking automatically.")
		}
		return *value.ExitCode
	}
	return 0
}

func writeSetupFailure(output io.Writer, problem, outcome string, detail error, sessionID string) {
	fmt.Fprintln(output, "Ghost cannot start securely.")
	fmt.Fprintln(output)
	fmt.Fprintln(output, problem)
	if outcome != "" {
		fmt.Fprintln(output, outcome)
	}
	if detail != nil {
		fmt.Fprintf(output, "Details: %v\n", detail)
	}
	if sessionID != "" {
		fmt.Fprintf(output, "Session: %s\n", sessionID)
	}
}

func writeRunFailure(output io.Writer, value session.Session, runErr error) {
	var preflightErr *ghruntime.PreflightError
	if errors.As(runErr, &preflightErr) {
		writeSetupFailure(output, preflightErr.UserMessage(), preflightGuidance(preflightErr), preflightErr.Err, value.ID)
		return
	}
	var unavailable *ghruntime.CommandUnavailableError
	if errors.As(runErr, &unavailable) {
		writeSetupFailure(output, fmt.Sprintf("Command %q is not available inside Ghost's pinned isolated runtime.", unavailable.Executable), "Choose a command provided by the runtime image, or invoke an available shell/tool instead.", nil, value.ID)
		return
	}
	if errors.Is(runErr, ghruntime.ErrSessionTimeout) {
		writeSetupFailure(output, "The command reached Ghost's configured session time limit.", "Ghost stopped and cleaned up the isolated process tree. Increase runtime.limits.timeout_seconds only when a longer run is expected.", nil, value.ID)
		return
	}
	var resourceLimit *ghruntime.ResourceLimitError
	if errors.As(runErr, &resourceLimit) {
		switch resourceLimit.Kind {
		case ghruntime.ResourceOOM:
			writeSetupFailure(output, "The isolated command reached its memory boundary.", "Ghost stopped and cleaned up the isolated process tree. Increase runtime.limits.memory_mib only when the workload is expected to need more memory.", nil, value.ID)
		case ghruntime.ResourcePIDs:
			writeSetupFailure(output, "The isolated command reached its process boundary.", "Ghost stopped and cleaned up the isolated process tree. Check for unexpected process growth before increasing runtime.limits.pids.", nil, value.ID)
		default:
			writeSetupFailure(output, "The isolated command reached a mandatory runtime boundary.", "Ghost stopped and cleaned up the isolated process tree.", nil, value.ID)
		}
		return
	}
	if errors.Is(runErr, context.Canceled) {
		writeSetupFailure(output, "The session was cancelled.", "Ghost stopped and cleaned up the isolated process tree.", nil, value.ID)
		return
	}
	if value.ExitCode == nil {
		writeSetupFailure(output, "A required security or runtime check failed.", "Ghost could not verify a completed execution. The session failed closed.", runErr, value.ID)
		return
	}
	fmt.Fprintln(output, "Ghost stopped the session because secure runtime execution failed.")
	fmt.Fprintf(output, "Details: %v\n", runErr)
	fmt.Fprintf(output, "Session: %s\n", value.ID)
}

func preflightGuidance(value *ghruntime.PreflightError) string {
	switch value.Area {
	case ghruntime.PreflightDocker:
		detail := strings.ToLower(value.Err.Error())
		if strings.Contains(detail, "cli not found") {
			return "The agent was not launched.\nNext: Install Docker and make sure 'docker' is on PATH, then rerun."
		}
		if strings.Contains(detail, "daemon is unavailable") {
			return "The agent was not launched.\nNext: Start Docker and confirm 'docker info' succeeds, then rerun."
		}
		return "The agent was not launched.\nNext: Use a Linux Docker daemon with the required cgroup limits and default seccomp profile."
	case ghruntime.PreflightIdentity:
		return "The agent was not launched.\nNext: Run Ghost as a non-root host user with a valid UID and GID."
	case ghruntime.PreflightWorkspace:
		return "The agent was not launched.\nNext: Use a real project directory that does not expose the host home or Docker socket."
	default:
		return "Ghost stopped before launching the agent.\nNext: Correct the reported problem, then rerun."
	}
}

func mayRequireNetwork(command []string) bool {
	if len(command) == 0 {
		return false
	}
	switch filepath.Base(command[0]) {
	case "curl", "wget", "git", "npm", "npx", "pnpm", "yarn", "pip", "pip3", "go", "cargo", "apt", "apt-get", "apk":
		return true
	default:
		return false
	}
}

func openSessionStore(ctx context.Context, root string) (*storage.Store, error) {
	databasePath := filepath.Join(root, config.RuntimeDirName, config.DatabaseName)
	if _, err := os.Lstat(databasePath); err == nil {
		return storage.Open(ctx, databasePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect Ghost database: %w", err)
	}
	if _, err := config.Load(filepath.Join(root, config.FileName)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("no Ghost project found; run 'ghost init'")
		}
		return nil, fmt.Errorf("cannot recreate Ghost state while ghost.yaml is invalid: %w", err)
	}
	return prepareProjectState(ctx, root)
}

func inspectSession(ctx context.Context, root, selector string, output io.Writer) error {
	store, err := openSessionStore(ctx, root)
	if err != nil {
		return err
	}
	defer store.Close()

	value, err := selectSession(ctx, store, selector)
	if err != nil {
		return err
	}
	storedEvents, err := store.Events(ctx, value.ID)
	if err != nil {
		return err
	}
	decoys, err := store.Decoys(ctx, value.ID)
	if err != nil {
		return err
	}
	printInspection(output, value, storedEvents, decoys)
	return nil
}

func graphSession(ctx context.Context, root, selector string, jsonOutput bool, output io.Writer) error {
	store, err := openSessionStore(ctx, root)
	if err != nil {
		return err
	}
	defer store.Close()

	value, err := selectSession(ctx, store, selector)
	if err != nil {
		return err
	}
	storedEvents, err := store.Events(ctx, value.ID)
	if err != nil {
		return err
	}
	graph := provenance.Build(value, storedEvents)
	if jsonOutput {
		if err := provenance.WriteJSON(output, graph); err != nil {
			return fmt.Errorf("write provenance JSON: %w", err)
		}
		return nil
	}
	provenance.WriteText(output, graph)
	return nil
}

func incidentsSession(ctx context.Context, root, selector string, jsonOutput bool, output io.Writer) error {
	store, err := openSessionStore(ctx, root)
	if err != nil {
		return err
	}
	defer store.Close()

	value, err := selectSession(ctx, store, selector)
	if err != nil {
		return err
	}
	storedEvents, err := store.Events(ctx, value.ID)
	if err != nil {
		return err
	}
	report := ghostincidents.Reconstruct(value, storedEvents)
	if jsonOutput {
		if err := ghostincidents.WriteJSON(output, report); err != nil {
			return fmt.Errorf("write incident JSON: %w", err)
		}
		return nil
	}
	ghostincidents.WriteText(output, report)
	return nil
}

type sessionReader interface {
	LatestSession(ctx context.Context) (session.Session, error)
	Session(ctx context.Context, id string) (session.Session, error)
}

func selectSession(ctx context.Context, store sessionReader, selector string) (session.Session, error) {
	var value session.Session
	var err error
	if selector == "latest" {
		value, err = store.LatestSession(ctx)
		if errors.Is(err, storage.ErrNotFound) {
			return session.Session{}, errors.New("no sessions recorded")
		}
	} else {
		value, err = store.Session(ctx, selector)
		if errors.Is(err, storage.ErrNotFound) {
			return session.Session{}, fmt.Errorf("session %q not found", selector)
		}
	}
	if err != nil {
		return session.Session{}, err
	}
	return value, nil
}

func printInspection(output io.Writer, value session.Session, storedEvents []events.Event, decoys []deception.Decoy) {
	fmt.Fprintln(output, "Ghost Session")
	fmt.Fprintln(output)
	table := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	fmt.Fprintf(table, "ID:\t%s\n", value.ID)
	fmt.Fprintf(table, "Status:\t%s\n", value.Status)
	fmt.Fprintf(table, "Runtime:\t%s\n", value.Runtime)
	if len(value.Command) > 0 {
		fmt.Fprintf(table, "Command:\t%s (arguments omitted)\n", formatCommand(value.Command[:1]))
	}
	fmt.Fprintf(table, "Started:\t%s\n", value.CreatedAt.Format(time.RFC3339Nano))
	if value.CompletedAt != nil {
		fmt.Fprintf(table, "Duration:\t%s\n", value.CompletedAt.Sub(value.CreatedAt).Round(time.Millisecond))
	} else {
		fmt.Fprintln(table, "Duration:\t-")
	}
	if value.ExitCode != nil {
		fmt.Fprintf(table, "Exit code:\t%d\n", *value.ExitCode)
	} else {
		fmt.Fprintln(table, "Exit code:\t-")
	}
	_ = table.Flush()

	decisions := map[string]int{"ALLOW": 0, "DENY": 0, "SHADOW": 0, "ASK": 0}
	networkEvents := make([]events.Event, 0)
	for _, event := range storedEvents {
		if event.Type == events.PolicyAllow || event.Type == events.PolicyDeny || event.Type == events.PolicyShadow || event.Type == events.PolicyAsk {
			if event.Decision != nil {
				decisions[string(*event.Decision)]++
			}
		}
		if event.Type == events.NetworkAllow || event.Type == events.NetworkDeny {
			networkEvents = append(networkEvents, event)
		}
	}
	incidentReport := ghostincidents.Reconstruct(value, storedEvents)
	summary := summarizeSecurity(value, storedEvents)
	triggered := 0
	for _, decoy := range decoys {
		if decoy.Triggered {
			triggered++
		}
	}
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Security")
	fmt.Fprintln(output)
	securityTable := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	homeMode := "DENY"
	if len(decoys) > 0 {
		homeMode = "SHADOW"
	}
	fmt.Fprintf(securityTable, "Home:\t%s\n", homeMode)
	fmt.Fprintf(securityTable, "Network:\t%s\n", strings.ToUpper(string(value.NetworkMode)))
	contained := "no"
	if value.IsContained() {
		contained = "yes"
	}
	fmt.Fprintf(securityTable, "Contained:\t%s\n", contained)
	fmt.Fprintf(securityTable, "Decisions:	ALLOW %d   DENY %d   SHADOW %d   ASK %d\n", decisions["ALLOW"], decisions["DENY"], decisions["SHADOW"], decisions["ASK"])
	fmt.Fprintf(securityTable, "Shadow resources:	%d\n", len(decoys))
	fmt.Fprintf(securityTable, "Triggered:	%d\n", triggered)
	fmt.Fprintf(securityTable, "Incidents:	%d\n", len(incidentReport.Incidents))
	fmt.Fprintf(securityTable, "Selected untrusted sources:\t%d\n", summary.UntrustedSources)
	fmt.Fprintf(securityTable, "Suspicious instruction sources:\t%d\n", summary.SuspiciousSources)
	if summary.ApprovalRequests > 0 {
		fmt.Fprintf(securityTable, "Approval requests:\t%d\n", summary.ApprovalRequests)
		fmt.Fprintf(securityTable, "Approved / denied:\t%d / %d\n", summary.ApprovalsGranted, summary.ApprovalsDenied)
	}
	fmt.Fprintln(securityTable, "Host home mounted:\tno")
	_ = securityTable.Flush()

	if len(decoys) > 0 {
		fmt.Fprintln(output)
		fmt.Fprintln(output, "Decoys")
		fmt.Fprintln(output)
		decoyTable := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
		fmt.Fprintln(decoyTable, "TYPE\tPATH\tSTATUS")
		for _, decoy := range decoys {
			status := "untouched"
			if decoy.Triggered {
				status = "TRIGGERED"
			}
			fmt.Fprintf(decoyTable, "%s\t%s\t%s\n", decoy.Type.DisplayName(), displayGuestPath(decoy.GuestPath), status)
		}
		_ = decoyTable.Flush()
	}

	if len(networkEvents) > 0 {
		fmt.Fprintln(output)
		fmt.Fprintln(output, "Network")
		fmt.Fprintln(output)
		networkTable := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
		fmt.Fprintln(networkTable, "TIME (UTC)\tHOST\tPORT\tMETHOD\tDECISION")
		for _, event := range networkEvents {
			host, _ := event.Metadata["host"].(string)
			port := metadataInteger(event.Metadata["port"])
			method, _ := event.Metadata["method"].(string)
			decision := "-"
			if event.Decision != nil {
				decision = string(*event.Decision)
			}
			fmt.Fprintf(networkTable, "%s\t%s\t%d\t%s\t%s\n", event.Timestamp.Format("15:04:05.000"), host, port, method, decision)
		}
		_ = networkTable.Flush()
	}

	if len(incidentReport.Incidents) > 0 {
		fmt.Fprintln(output)
		fmt.Fprintln(output, "Incident summary")
		for _, incident := range incidentReport.Incidents {
			fmt.Fprintf(output, "\n%s  %s\n", incident.Severity, incident.Type)
			fmt.Fprintln(output, incident.Summary)
			fmt.Fprintf(output, "Evidence: %d events\n", len(incident.EvidenceEventIDs))
		}
		fmt.Fprintf(output, "\nDetails: ghost incidents %s\n", value.ID)
	}

	for _, event := range storedEvents {
		if message, ok := event.Metadata["error"].(string); ok && message != "" {
			fmt.Fprintf(output, "Error:     %s\n", message)
			break
		}
	}
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Events")
	fmt.Fprintln(output)
	eventTable := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(eventTable, "TIME (UTC)\tTYPE\tACTION\tDECISION")
	for _, event := range storedEvents {
		decision := "-"
		if event.Decision != nil {
			decision = string(*event.Decision)
		}
		action := event.Action
		if action == "" {
			action = "-"
		}
		fmt.Fprintf(eventTable, "%s\t%s\t%s\t%s\n", event.Timestamp.Format("15:04:05.000"), event.Type, action, decision)
	}
	_ = eventTable.Flush()
}

func metadataInteger(value any) int {
	switch number := value.(type) {
	case float64:
		return int(number)
	case int:
		return number
	default:
		return 0
	}
}

func displayGuestPath(path string) string {
	if path == deception.GuestHome {
		return "~"
	}
	if strings.HasPrefix(path, deception.GuestHome+"/") {
		return "~" + strings.TrimPrefix(path, deception.GuestHome)
	}
	return path
}

var safeArgument = regexp.MustCompile(`^[A-Za-z0-9_./:@%+=,-]+$`)

func formatCommand(command []string) string {
	formatted := make([]string, len(command))
	for index, argument := range command {
		if argument != "" && safeArgument.MatchString(argument) {
			formatted[index] = argument
		} else {
			formatted[index] = strconv.Quote(argument)
		}
	}
	return strings.Join(formatted, " ")
}

func printHelp(output io.Writer) {
	fmt.Fprintln(output, `Ghost — a deception-aware security runtime for autonomous AI agents.

Usage:
  ghost init
  ghost run [--] <command> [arguments...]
  ghost inspect [session-id|latest]
  ghost graph [session-id|latest] [--json]
  ghost incidents [session-id|latest] [--json]
  ghost bench [--json] [--require-all] [--scenario <name>]
  ghost version

Commands:
  init       Create secure project defaults
  run        Preflight and execute in the configured isolated runtime
  inspect    Show a persisted session and its event timeline (default: latest)
  graph      Reconstruct observed and temporal session relationships (default: latest)
  incidents  Reconstruct concise security-relevant event sequences (default: latest)
  bench      Demonstrate specific Ghost security properties locally
  version    Print the Ghost version

Ghost requires Docker for execution and never falls back to the host.
GhostBench reports unavailable Docker-dependent scenarios as SKIP, never PASS.`)
}
