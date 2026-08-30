package runtime

import (
	"context"
	"io"
	"time"
)

type ShadowResource struct {
	DecoyID   string
	GuestPath string
}

type AccessEvidence struct {
	DecoyID    string
	GuestPath  string
	DetectedAt time.Time
	Events     string
}

type RunRequest struct {
	Command           []string
	Workspace         string
	WorkspaceReadOnly bool
	SessionID         string
	SessionDir        string
	SyntheticHome     string
	ShadowResources   []ShadowResource
	Stdin             io.Reader
	Stdout            io.Writer
	Stderr            io.Writer
}

type RunResult struct {
	Started  bool
	ExitCode int
	Accesses []AccessEvidence
}

type Runtime interface {
	Name() string
	Run(ctx context.Context, request RunRequest) (RunResult, error)
}
