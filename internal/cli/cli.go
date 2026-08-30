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
	"text/tabwriter"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/config"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
	"github.com/rappidAI-research/rappid-ghost/internal/storage"
)

const Version = "0.1.0"

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
			fmt.Fprintln(stdout, "Usage: ghost run -- <command> [arguments...]")
			return 0
		}
		command, err := parseRunArgs(args[1:])
		if err != nil {
			fmt.Fprintf(stderr, "ghost: %v\n", err)
			return 2
		}
		return runCommand(ctx, root, command, stdin, stdout, stderr)
	case "inspect":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "ghost: usage: ghost inspect <session-id|latest>")
			return 2
		}
		if err := inspectSession(ctx, root, args[1], stdout); err != nil {
			fmt.Fprintf(stderr, "ghost: %v\n", err)
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
		fmt.Fprintf(stderr, "ghost: unknown command %q\nRun 'ghost --help' for usage.\n", args[0])
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

	runtimeDir := filepath.Join(root, config.RuntimeDirName)
	sessionsDir := filepath.Join(runtimeDir, config.SessionsDir)
	if err := ensurePrivateDirectory(runtimeDir); err != nil {
		return fmt.Errorf("prepare Ghost runtime directory: %w", err)
	}
	if err := ensurePrivateDirectory(sessionsDir); err != nil {
		return fmt.Errorf("prepare Ghost sessions directory: %w", err)
	}
	store, err := storage.Open(ctx, filepath.Join(runtimeDir, config.DatabaseName))
	if err != nil {
		return err
	}
	if err := store.Close(); err != nil {
		return fmt.Errorf("close Ghost database: %w", err)
	}

	if created {
		fmt.Fprintln(output, "Ghost initialized.")
		fmt.Fprintln(output, "  Config: ghost.yaml")
		fmt.Fprintln(output, "  Data:   .ghost/")
	} else {
		fmt.Fprintln(output, "Ghost already initialized; existing ghost.yaml preserved.")
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

func parseRunArgs(args []string) ([]string, error) {
	if len(args) < 2 || args[0] != "--" {
		return nil, errors.New("usage: ghost run -- <command> [arguments...]")
	}
	return append([]string(nil), args[1:]...), nil
}

func runCommand(ctx context.Context, root string, command []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cfg, err := config.Load(filepath.Join(root, config.FileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(stderr, "ghost: project is not initialized; run 'ghost init'")
		} else {
			fmt.Fprintf(stderr, "ghost: %v\n", err)
		}
		return 1
	}
	runtimeDir := filepath.Join(root, config.RuntimeDirName)
	if info, err := os.Stat(runtimeDir); err != nil || !info.IsDir() {
		fmt.Fprintln(stderr, "ghost: project is not initialized; run 'ghost init'")
		return 1
	}

	store, err := storage.Open(ctx, filepath.Join(runtimeDir, config.DatabaseName))
	if err != nil {
		fmt.Fprintf(stderr, "ghost: %v\n", err)
		return 1
	}
	defer store.Close()

	var runner ghruntime.Runtime
	switch cfg.Runtime.Provider {
	case "docker":
		runner = ghruntime.NewDocker()
	default:
		fmt.Fprintf(stderr, "ghost: unsupported runtime provider %q\n", cfg.Runtime.Provider)
		return 1
	}
	manager := session.NewManager(store, runner)
	value, runErr := manager.Run(ctx, ghruntime.RunRequest{
		Command:           command,
		Workspace:         root,
		WorkspaceReadOnly: cfg.Workspace.Mode == "read-only",
		Stdin:             stdin,
		Stdout:            stdout,
		Stderr:            stderr,
	})
	if runErr != nil {
		fmt.Fprintf(stderr, "ghost: %v\nSession: %s\n", runErr, value.ID)
		return 1
	}
	if value.ExitCode == nil {
		fmt.Fprintf(stderr, "ghost: isolated command produced no exit status\nSession: %s\n", value.ID)
		return 1
	}
	fmt.Fprintf(stdout, "Ghost session %s: %s (exit %d)\n", value.ID, value.Status, *value.ExitCode)
	if *value.ExitCode != 0 {
		return *value.ExitCode
	}
	return 0
}

func inspectSession(ctx context.Context, root, selector string, output io.Writer) error {
	databasePath := filepath.Join(root, config.RuntimeDirName, config.DatabaseName)
	if _, err := os.Stat(databasePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("no Ghost database found; run 'ghost init'")
		}
		return fmt.Errorf("inspect Ghost database: %w", err)
	}
	store, err := storage.Open(ctx, databasePath)
	if err != nil {
		return err
	}
	defer store.Close()

	var value session.Session
	if selector == "latest" {
		value, err = store.LatestSession(ctx)
		if errors.Is(err, storage.ErrNotFound) {
			return errors.New("no sessions recorded")
		}
	} else {
		value, err = store.Session(ctx, selector)
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("session %q not found", selector)
		}
	}
	if err != nil {
		return err
	}
	storedEvents, err := store.Events(ctx, value.ID)
	if err != nil {
		return err
	}
	printInspection(output, value, storedEvents)
	return nil
}

func printInspection(output io.Writer, value session.Session, storedEvents []events.Event) {
	fmt.Fprintln(output, "Ghost Session")
	fmt.Fprintln(output)
	table := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	fmt.Fprintf(table, "ID:\t%s\n", value.ID)
	fmt.Fprintf(table, "Status:\t%s\n", value.Status)
	fmt.Fprintf(table, "Runtime:\t%s\n", value.Runtime)
	fmt.Fprintf(table, "Command:\t%s\n", formatCommand(value.Command))
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
  ghost run -- <command> [arguments...]
  ghost inspect <session-id|latest>
  ghost version

Commands:
  init      Initialize Ghost in the current project
  run       Execute a command in the configured isolated runtime
  inspect   Show a persisted session and its event timeline
  version   Print the Ghost version

Ghost v0.1 requires Docker for execution and never falls back to the host.`)
}
