package runtime

import (
	"context"
	"io"
	"time"

	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
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
	Sequence   int
}

type NetworkEvidence struct {
	DetectedAt time.Time
	Sequence   int
	Scheme     string
	Host       string
	Port       int
	Method     string
	Decision   policy.Decision
	Contained  bool
}

type RunRequest struct {
	Command           []string
	Workspace         string
	WorkspaceReadOnly bool
	SessionID         string
	SessionDir        string
	SyntheticHome     string
	ShadowResources   []ShadowResource
	NetworkPolicy     ghostnetwork.Policy
	ContainOnDecoy    bool
	Stdin             io.Reader
	Stdout            io.Writer
	Stderr            io.Writer
}

type RunResult struct {
	Started   bool
	ExitCode  int
	Accesses  []AccessEvidence
	Network   []NetworkEvidence
	Contained bool
}

type Runtime interface {
	Name() string
	Run(ctx context.Context, request RunRequest) (RunResult, error)
}
