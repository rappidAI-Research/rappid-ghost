package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/approval"
	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
)

var approvalRequestName = regexp.MustCompile(`^approval\.[A-Za-z0-9]+$`)

type approvalWireRequest struct {
	ID     string `json:"id"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Method string `json:"method"`
}

type approvalBroker struct {
	controller    *approval.Controller
	requestDir    string
	responseDir   string
	security      approval.SecurityContext
	sessionID     string
	networkPolicy ghostnetwork.Policy
	cancel        context.CancelFunc
	done          chan struct{}

	workers sync.WaitGroup
	errMu   sync.Mutex
	err     error
}

func startApprovalBroker(parent context.Context, request RunRequest, observation observationPaths) (*approvalBroker, error) {
	if len(request.NetworkPolicy.Ask) == 0 {
		return nil, nil
	}
	controller, err := approval.NewController(request.SessionID, request.ApprovalHandler, request.ApprovalTimeout)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	broker := &approvalBroker{
		controller: controller, requestDir: observation.approvalRequests,
		responseDir: observation.approvalResponses, security: request.ApprovalContext,
		sessionID:     request.SessionID,
		networkPolicy: request.NetworkPolicy,
		cancel:        cancel, done: make(chan struct{}),
	}
	go broker.run(ctx)
	return broker, nil
}

func (b *approvalBroker) run(ctx context.Context) {
	defer close(b.done)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	seen := make(map[string]bool)
	for {
		if err := b.scan(ctx, seen); err != nil {
			b.setError(err)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (b *approvalBroker) scan(ctx context.Context, seen map[string]bool) error {
	entries, err := os.ReadDir(b.requestDir)
	if err != nil {
		return fmt.Errorf("read approval requests: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := entry.Name()
		if seen[name] {
			continue
		}
		if entry.IsDir() || !approvalRequestName.MatchString(name) {
			return fmt.Errorf("invalid approval request artifact %q", name)
		}
		seen[name] = true
		b.workers.Add(1)
		go func() {
			defer b.workers.Done()
			if err := b.resolve(ctx, name); err != nil {
				b.setError(err)
			}
		}()
	}
	return nil
}

func (b *approvalBroker) resolve(ctx context.Context, name string) error {
	path := filepath.Join(b.requestDir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect approval request: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 4096 {
		return errors.New("approval request must be a small regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read approval request: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("consume approval request: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire approvalWireRequest
	if err := decoder.Decode(&wire); err != nil {
		return errors.New("decode approval request")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("decode approval request: trailing data")
	}
	if wire.ID != name {
		return errors.New("approval request identity mismatch")
	}
	expected, policyErr := b.networkPolicy.Decision(wire.Host, wire.Port, policy.StateNormal)
	if policyErr != nil || expected != policy.Ask {
		return errors.New("approval request is outside configured ASK policy")
	}
	resolution := b.controller.Resolve(ctx, approval.Request{
		ID: wire.ID, SessionID: b.sessionID, Scheme: wire.Scheme,
		Host: wire.Host, Port: wire.Port, Method: wire.Method,
		Reason: "destination requires explicit session approval", Context: b.security,
	})
	response := fmt.Sprintf("%s %s %s\n", resolution.Scope, resolution.Source, resolution.Reason)
	temporary := filepath.Join(b.responseDir, name+".host-tmp")
	final := filepath.Join(b.responseDir, name)
	if err := writeExclusive(temporary, []byte(response), 0o600); err != nil {
		return fmt.Errorf("write approval response: %w", err)
	}
	if err := os.Rename(temporary, final); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("publish approval response: %w", err)
	}
	return nil
}

func (b *approvalBroker) setError(err error) {
	b.errMu.Lock()
	b.err = errors.Join(b.err, err)
	b.errMu.Unlock()
	// A protocol or filesystem error invalidates the approval channel for the
	// entire session. Cancel every in-flight resolution so no later request can
	// be granted through a partially failed broker.
	b.cancel()
}

func (b *approvalBroker) stop() error {
	if b == nil {
		return nil
	}
	b.cancel()
	<-b.done
	b.workers.Wait()
	b.errMu.Lock()
	defer b.errMu.Unlock()
	return b.err
}
