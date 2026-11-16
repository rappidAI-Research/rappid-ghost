package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/config"
)

const pruneUsage = "ghost prune --older-than-days N [--dry-run] [--json]"

type pruneOptions struct {
	days         int
	dryRun, json bool
}

func parsePruneArgs(args []string) (pruneOptions, error) {
	var options pruneOptions
	set := flag.NewFlagSet("prune", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.IntVar(&options.days, "older-than-days", 0, "")
	set.BoolVar(&options.dryRun, "dry-run", false, "")
	set.BoolVar(&options.json, "json", false, "")
	if err := set.Parse(args); err != nil {
		return options, fmt.Errorf("%s: %w", pruneUsage, err)
	}
	if set.NArg() != 0 || options.days < 1 || options.days > 3650 {
		return options, errors.New(pruneUsage + " (N must be 1..3650)")
	}
	return options, nil
}

func pruneCommand(ctx context.Context, root string, options pruneOptions, output io.Writer) error {
	store, err := openSessionStore(ctx, root)
	if err != nil {
		return err
	}
	defer store.Close()
	directory := filepath.Join(root, config.RuntimeDirName, config.SessionsDir)
	if err = ensurePrivateDirectory(directory); err != nil {
		return fmt.Errorf("prepare retention directory: %w", err)
	}
	cutoff := time.Now().UTC().Add(-time.Duration(options.days) * 24 * time.Hour)
	if !options.dryRun && !options.json {
		fmt.Fprintf(output, "Pruning completed, cleaned sessions before %s; interrupted maintenance resumes before the next run.\n", cutoff.Format(time.RFC3339))
	}
	report, err := store.Prune(ctx, directory, cutoff, options.dryRun)
	if err != nil {
		return err
	}
	if options.json {
		return json.NewEncoder(output).Encode(report)
	}
	if options.dryRun {
		fmt.Fprintf(output, "Eligible completed sessions: %d. Previous maintenance pending: %t.\n", report.Eligible, report.Pending)
		fmt.Fprintln(output, "Run the same command without --dry-run to remove their database records and retained session directories.")
	} else {
		fmt.Fprintf(output, "Removed %d completed session(s) and their retained evidence.\n", report.Removed)
	}
	return nil
}
