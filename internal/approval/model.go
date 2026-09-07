// Package approval implements narrow, session-scoped user approval decisions.
// It is not a policy engine: callers may request approval only after hard
// policy boundaries have already established that ASK is a valid outcome.
package approval

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const DefaultTimeout = 30 * time.Second

type Scope string

const (
	Deny         Scope = "DENY"
	AllowOnce    Scope = "ALLOW_ONCE"
	AllowSession Scope = "ALLOW_SESSION"
)

func (s Scope) Valid() bool {
	return s == Deny || s == AllowOnce || s == AllowSession
}

type Source string

const (
	SourceUser            Source = "USER_DECISION"
	SourceSessionApproval Source = "SESSION_APPROVAL"
	SourceAutomatic       Source = "AUTOMATIC_FAIL_CLOSED"
	SourcePolicy          Source = "AUTOMATIC_POLICY"
)

func (s Source) Valid() bool {
	return s == SourceUser || s == SourceSessionApproval || s == SourceAutomatic || s == SourcePolicy
}

type SecurityContext struct {
	UntrustedContentObserved bool   `json:"untrusted_content_observed"`
	SuspiciousInstructions   bool   `json:"suspicious_instructions_observed"`
	PromptSeverity           string `json:"prompt_severity,omitempty"`
}

type Request struct {
	ID            string
	SessionID     string
	Scheme        string
	Host          string
	Port          int
	Method        string
	Reason        string
	Timeout       time.Duration
	Context       SecurityContext
	AllowedScopes []Scope
}

func (r Request) Resource() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

func (r Request) key() string {
	return r.Scheme + "\x00" + r.Host + "\x00" + fmt.Sprint(r.Port) + "\x00" + r.Method
}

func (r Request) Validate() error {
	if r.ID == "" || r.SessionID == "" || r.Host == "" || r.Reason == "" {
		return errors.New("approval request requires ID, session, destination, and reason")
	}
	if r.Scheme != "http" && r.Scheme != "https" {
		return errors.New("approval request has unsupported scheme")
	}
	if (r.Scheme == "http" && r.Port != 80) || (r.Scheme == "https" && r.Port != 443) {
		return errors.New("approval request has unsupported port")
	}
	if r.Method == "" || strings.ContainsAny(r.Method+r.Host, " \t\r\n\"\\") {
		return errors.New("approval request requires an action")
	}
	if r.Timeout <= 0 {
		return errors.New("approval request requires a positive timeout")
	}
	if len(r.AllowedScopes) != 3 || r.AllowedScopes[0] != AllowOnce || r.AllowedScopes[1] != AllowSession || r.AllowedScopes[2] != Deny {
		return errors.New("approval request has invalid scopes")
	}
	return nil
}

type Response struct {
	Scope Scope
}

type Resolution struct {
	Scope   Scope
	Source  Source
	Reason  string
	Granted bool
}

type EventKind string

const (
	Required    EventKind = "APPROVAL_REQUIRED"
	Granted     EventKind = "APPROVAL_GRANTED"
	Denied      EventKind = "APPROVAL_DENIED"
	Unavailable EventKind = "APPROVAL_UNAVAILABLE"
	Expired     EventKind = "APPROVAL_EXPIRED"
)

func (k EventKind) Valid() bool {
	switch k {
	case Required, Granted, Denied, Unavailable, Expired:
		return true
	default:
		return false
	}
}

func (r Resolution) EventKind() EventKind {
	if r.Granted {
		return Granted
	}
	if r.Reason == "approval_expired" {
		return Expired
	}
	if r.Source == SourceUser {
		return Denied
	}
	return Unavailable
}

type Handler interface {
	Decide(context.Context, Request) (Response, error)
}

// Controller owns approval state for exactly one session. Resolution is
// serialized so concurrent requests cannot consume or create each other's
// grants. Session grants are keyed by exact scheme, host, port, and action.
type Controller struct {
	sessionID string
	handler   Handler
	timeout   time.Duration

	mu            sync.Mutex
	sessionGrants map[string]struct{}
}

func NewController(sessionID string, handler Handler, timeout time.Duration) (*Controller, error) {
	if sessionID == "" {
		return nil, errors.New("approval controller requires a session ID")
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Controller{
		sessionID: sessionID, handler: handler, timeout: timeout,
		sessionGrants: make(map[string]struct{}),
	}, nil
}

func (c *Controller) Resolve(ctx context.Context, request Request) Resolution {
	c.mu.Lock()
	defer c.mu.Unlock()

	request.Timeout = c.timeout
	request.AllowedScopes = []Scope{AllowOnce, AllowSession, Deny}
	if request.SessionID != c.sessionID {
		return failClosed("session_mismatch")
	}
	if err := request.Validate(); err != nil {
		return failClosed("invalid_request")
	}
	if ctx.Err() != nil {
		return failClosed("approval_unavailable")
	}
	if _, ok := c.sessionGrants[request.key()]; ok {
		return Resolution{Scope: AllowSession, Source: SourceSessionApproval, Reason: "matching_session_approval", Granted: true}
	}
	if c.handler == nil {
		return failClosed("approval_unavailable")
	}

	decisionCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	type result struct {
		response Response
		err      error
	}
	resultChannel := make(chan result, 1)
	go func() {
		response, err := c.handler.Decide(decisionCtx, request)
		resultChannel <- result{response: response, err: err}
	}()
	var response Response
	var err error
	select {
	case value := <-resultChannel:
		response, err = value.response, value.err
	case <-decisionCtx.Done():
		err = decisionCtx.Err()
	}
	// Cancellation always wins over a concurrent response. An approval that
	// arrives after its operation is no longer live must not be reusable.
	if decisionCtx.Err() != nil {
		err = decisionCtx.Err()
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(decisionCtx.Err(), context.DeadlineExceeded) {
			return Resolution{Scope: Deny, Source: SourceAutomatic, Reason: "approval_expired"}
		}
		return failClosed("approval_unavailable")
	}
	if !response.Scope.Valid() {
		return failClosed("malformed_response")
	}
	switch response.Scope {
	case AllowOnce:
		return Resolution{Scope: AllowOnce, Source: SourceUser, Reason: "user_allowed_once", Granted: true}
	case AllowSession:
		c.sessionGrants[request.key()] = struct{}{}
		return Resolution{Scope: AllowSession, Source: SourceUser, Reason: "user_allowed_for_session", Granted: true}
	default:
		return Resolution{Scope: Deny, Source: SourceUser, Reason: "user_denied"}
	}
}

func failClosed(reason string) Resolution {
	return Resolution{Scope: Deny, Source: SourceAutomatic, Reason: reason}
}
