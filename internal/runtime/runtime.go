package runtime

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/approval"
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
	DetectedAt    time.Time
	Sequence      int
	Scheme        string
	Host          string
	Port          int
	Method        string
	Decision      policy.Decision
	SecurityState policy.SecurityState
	RequestID     string
}

type ApprovalEvidence struct {
	DetectedAt    time.Time
	Sequence      int
	RequestID     string
	Scheme        string
	Host          string
	Port          int
	Method        string
	Kind          approval.EventKind
	Scope         approval.Scope
	Source        approval.Source
	Reason        string
	SecurityState policy.SecurityState
}

type RunRequest struct {
	Limits            *Limits
	Command           []string
	Workspace         string
	WorkspaceReadOnly bool
	SessionID         string
	SessionDir        string
	SyntheticHome     string
	ShadowResources   []ShadowResource
	NetworkPolicy     ghostnetwork.Policy
	ContainOnDecoy    bool
	ApprovalHandler   approval.Handler
	ApprovalTimeout   time.Duration
	ApprovalContext   approval.SecurityContext
	Stdin             io.Reader
	Stdout            io.Writer
	Stderr            io.Writer
}

type RunResult struct {
	Resources     []ResourceEvidence
	Started       bool
	ExitCode      int
	Accesses      []AccessEvidence
	Network       []NetworkEvidence
	Approvals     []ApprovalEvidence
	SecurityState policy.SecurityState
	// CleanupPending is set when Docker-owned resources could not be proven
	// absent after execution. Session recovery must retry before another run.
	CleanupPending bool
}

type Runtime interface {
	Name() string
	Run(ctx context.Context, request RunRequest) (RunResult, error)
}

// PreparedRun is a validated, single-use runtime execution. Implementations
// must retain the security properties established by Preflight and must fail
// closed if execution cannot proceed with those properties intact.
type PreparedRun interface {
	Run(ctx context.Context) (RunResult, error)
}

// Preflighter lets a runtime validate its mandatory static prerequisites
// before Ghost records PROCESS_START. Runtime remains intentionally small so
// alternate providers are not required to implement a duplicate validation
// path; callers safely fall back to Runtime.Run when this interface is absent.
type Preflighter interface {
	Preflight(ctx context.Context, request RunRequest) (PreparedRun, error)
}

type PreflightArea string

const (
	PreflightPolicy       PreflightArea = "policy"
	PreflightWorkspace    PreflightArea = "workspace"
	PreflightRuntimeState PreflightArea = "runtime_state"
	PreflightDocker       PreflightArea = "docker"
	PreflightIdentity     PreflightArea = "identity"
)

// PreflightError retains the technical cause while giving the CLI a stable,
// non-secret category from which to produce a useful human explanation.
type PreflightError struct {
	Area PreflightArea
	Err  error
}

// CommandUnavailableError identifies an executable that Docker could not
// start inside the isolated runtime. It retains only the executable name; no
// command arguments or guest output are copied into durable failure details.
type CommandUnavailableError struct {
	Executable string
}

func (e *CommandUnavailableError) Error() string {
	return fmt.Sprintf("command %q is unavailable inside the isolated runtime", e.Executable)
}

// ResourceLimitError identifies an observed mandatory runtime boundary. It is
// operational evidence and does not classify the command as malicious.
type ResourceLimitError struct {
	Kind string
}

func (e *ResourceLimitError) Error() string {
	return fmt.Sprintf("mandatory runtime limit reached: %s", e.Kind)
}

// CleanupVerificationError means the command may have stopped, but Docker
// could not prove every exactly owned runtime object absent. The durable
// session marker makes a later invocation retry strict recovery.
type CleanupVerificationError struct {
	Err error
}

func (e *CleanupVerificationError) Error() string {
	return fmt.Sprintf("runtime cleanup could not be verified: %v", e.Err)
}

func (e *CleanupVerificationError) Unwrap() error { return e.Err }

func (e *PreflightError) Error() string {
	return fmt.Sprintf("%s preflight: %v", e.Area, e.Err)
}

func (e *PreflightError) Unwrap() error { return e.Err }

func (e *PreflightError) UserMessage() string {
	switch e.Area {
	case PreflightPolicy:
		return "The runtime policy is invalid."
	case PreflightWorkspace:
		return "The workspace cannot be exposed safely."
	case PreflightRuntimeState:
		return "Ghost runtime state is unsafe or incomplete."
	case PreflightDocker:
		return "Docker runtime is unavailable."
	case PreflightIdentity:
		return "A safe non-root container identity is unavailable."
	default:
		return "The required isolation boundary could not be verified."
	}
}

// Recoverer removes runtime resources belonging to sessions whose persistent
// state proves that a previous Ghost run did not reach a terminal state.
// Implementations must reject resources whose ownership is ambiguous.
type Recoverer interface {
	Recover(ctx context.Context, sessionIDs []string) error
}

// RecoveryStateReader reads durable enforcement state after Recover has stopped
// the interrupted runtime. It must not infer missing access or approval events.
type RecoveryStateReader interface {
	RecoveredSecurityState(context.Context, string) (policy.SecurityState, error)
}
