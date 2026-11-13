package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rappidAI-research/rappid-ghost/internal/bridge"
	"github.com/rappidAI-research/rappid-ghost/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(os.Args) > 1 && os.Args[1] == "_broker-agent" {
		os.Exit(bridge.ExecAgent(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "_broker-bridge" {
		os.Exit(bridge.Run(ctx, os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(cli.Execute(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
