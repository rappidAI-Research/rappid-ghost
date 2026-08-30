package runtime

import (
	"context"
	"io"
)

type RunRequest struct {
	Command           []string
	Workspace         string
	WorkspaceReadOnly bool
	Stdin             io.Reader
	Stdout            io.Writer
	Stderr            io.Writer
}

type RunResult struct {
	Started  bool
	ExitCode int
}

type Runtime interface {
	Name() string
	Run(ctx context.Context, request RunRequest) (RunResult, error)
}
