package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const MaxRequestBytes = 1024 * 1024
const MaxResponseBytes = 8 * 1024 * 1024

type Event struct {
	ID        string
	Time      time.Time
	Kind      string // admission, denial, completion
	Operation string // static configured tool name or model path, never a resource ID
	Reason    string // closed host-generated outcome code
}

type Options struct {
	Audit func(context.Context, Event) error
	Check func(context.Context) error // current containment / trusted revocation
	Fence func(context.Context) error // ordered sentinel barrier before admission
}

type Server struct {
	handlers   sync.WaitGroup
	stopping   bool
	budgetOnce sync.Once
	tokens     float64
	lastToken  time.Time
	cfg        Config
	options    Options
	model, app *upstream
	ctx        context.Context
	cancel     context.CancelFunc
	expires    time.Time
	requests   atomic.Int64
	slots      chan struct{}
	mu         sync.Mutex
	replay     map[string]bool
	err        error
}

func New(ctx context.Context, cfg Config, options Options) (*Server, error) {
	cfg = cfg.Snapshot()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !cfg.Enabled() || options.Audit == nil || options.Check == nil {
		return nil, errors.New("broker requires explicit configuration, audit persistence and authoritative session state")
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	s := &Server{cfg: cfg, options: options, ctx: sessionCtx, cancel: cancel, expires: time.Now().Add(time.Duration(cfg.Lifetime()) * time.Second), slots: make(chan struct{}, 4), replay: map[string]bool{}, tokens: 8, lastToken: time.Now()}
	var err error
	if cfg.Model != nil {
		s.model, err = prepareUpstream(ctx, cfg.Model.Endpoint)
		if err != nil {
			cancel()
			return nil, err
		}
	}
	if cfg.Application != nil {
		s.app, err = prepareUpstream(ctx, *cfg.Application)
		if err != nil {
			s.Close()
			return nil, err
		}
	}
	return s, nil
}
func (s *Server) Close() {
	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()
	s.cancel()
	if s.model != nil {
		s.model.close()
	}
	if s.app != nil {
		s.app.close()
	}
}
func (s *Server) Err() error { s.mu.Lock(); defer s.mu.Unlock(); return s.err }
func (s *Server) fail(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
	s.cancel()
}
func (s *Server) check(ctx context.Context) error {
	if s.ctx.Err() != nil {
		return errors.New("broker inactive")
	}
	if !time.Now().Before(s.expires) {
		s.fail(errors.New("broker capability expired"))
		return errors.New("broker expired")
	}
	if err := s.options.Check(ctx); err != nil {
		s.fail(errors.New("broker capability revoked or contained"))
		return err
	}
	return nil
}
func (s *Server) rateAllowed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.tokens += now.Sub(s.lastToken).Seconds() * 2
	s.lastToken = now
	if s.tokens > 8 {
		s.tokens = 8
	}
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}
func (s *Server) audit(ctx context.Context, kind, operation, reason string) error {
	event := Event{ID: rand.Text(), Time: time.Now().UTC(), Kind: kind, Operation: operation, Reason: reason}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := s.options.Audit(auditCtx, event); err != nil {
		s.fail(errors.New("broker audit persistence failed"))
		return err
	}
	return nil
}
func (s *Server) deny(w http.ResponseWriter, r *http.Request, op, reason string, status int) {
	if err := s.audit(r.Context(), "denial", op, reason); err != nil {
		status = 503
	}
	if r.URL.Path == "/mcp" {
		code := -32602
		if reason == "unsupported_mcp_method" {
			code = -32601
			status = 404
		}
		if reason == "mcp_metadata_mismatch" {
			code = -32020
		}
		if reason == "unsupported_mcp_version" {
			code = -32022
		}
		id, _ := r.Context().Value(mcpIDKey{}).(json.RawMessage)
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		// Never echo an arbitrary malformed body. A valid bounded scalar ID alone
		// may be returned in the standard protocol error envelope.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		errorData := map[string]any{"code": code, "message": "Ghost broker denied: " + reason}
		if code == -32022 {
			errorData["data"] = map[string]any{"supported": []string{MCPVersion}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": errorData})
		return
	}
	http.Error(w, "Ghost broker denied: "+reason, status)
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		http.Error(w, "broker stopped", 503)
		return
	}
	s.handlers.Add(1)
	s.mu.Unlock()
	defer s.handlers.Done()
	if s.requests.Add(1) > int64(s.cfg.RequestBudget()) {
		s.budgetOnce.Do(func() { _ = s.audit(r.Context(), "denial", "broker", "request_budget") })
		s.fail(errors.New("broker request budget exhausted"))
		http.Error(w, "broker request budget exhausted", 429)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		s.deny(w, r, "broker", "concurrency_limit", 429)
		return
	}
	contentType, _, mimeErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if !s.rateAllowed() {
		s.deny(w, r, "broker", "rate_limit", 429)
		return
	}
	if r.Header.Get("Origin") != "" || r.Header.Get("Content-Encoding") != "" || mimeErr != nil || contentType != "application/json" {
		s.deny(w, r, "broker", "unsupported_origin_or_encoding", 403)
		return
	}
	if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.RawPath != "" || r.URL.IsAbs() || r.Host != "ghost-broker" || r.ContentLength > MaxRequestBytes || len(r.Header.Values("Content-Type")) != 1 {
		s.deny(w, r, "broker", "invalid_request", 400)
		return
	}
	if err := s.check(r.Context()); err != nil {
		s.deny(w, r, "broker", "inactive_or_contained", 403)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBytes+1))
	if err != nil || len(data) > MaxRequestBytes || validJSON(data) != nil {
		s.deny(w, r, "broker", "invalid_body", 400)
		return
	}
	if r.URL.Path == "/mcp" {
		var envelope struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal(data, &envelope)
		if validMCPID(envelope.ID) {
			r = r.WithContext(context.WithValue(r.Context(), mcpIDKey{}, envelope.ID))
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	// Cancel in-flight I/O promptly on containment or session expiry. No claim
	// is made to undo bytes or effects already delivered before revocation.
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if s.check(ctx) != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-done }()
	if s.options.Fence != nil {
		if err = s.options.Fence(ctx); err != nil {
			s.deny(w, r, "broker", "containment_fence", 403)
			return
		}
	}
	if s.check(ctx) != nil {
		s.deny(w, r, "broker", "inactive_or_contained", 403)
		return
	}
	switch r.URL.Path {
	case "/v1/responses", "/v1/chat/completions":
		s.modelRequest(ctx, w, r, data)
	case "/ghost/tools/call":
		s.toolRequest(ctx, w, r, data)
	case "/mcp":
		s.mcpRequest(ctx, w, r, data)
	default:
		s.deny(w, r, "broker", "unregistered_route", 404)
	}
}

func (s *Server) forward(ctx context.Context, target *upstream, path string, data []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", target.origin+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if target.token != "" {
		req.Header.Set("Authorization", "Bearer "+target.token)
	}
	return target.client.Do(req)
}

// ServeUnix never opens a host TCP listener. The directory is exactly owned by
// this session and exposed read-only, without credentials, to one container.
func (s *Server) ServeUnix(sessionID string) (string, func() error, error) {
	dir, err := createDirectory(sessionID)
	if err != nil {
		return "", nil, err
	}
	path := dir + "/broker.sock"
	listener, err := net.Listen("unix", path)
	if err != nil {
		_ = Cleanup(sessionID)
		return "", nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		listener.Close()
		_ = Cleanup(sessionID)
		return "", nil, err
	}
	server := &http.Server{Handler: s, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 * 1024, ErrorLog: discardLogger()}
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := server.Serve(&limitedListener{Listener: listener, slots: make(chan struct{}, 16)}); err != nil && !errors.Is(err, http.ErrServerClosed) && s.ctx.Err() == nil {
			s.fail(errors.New("broker listener failed"))
		}
	})
	stop := context.AfterFunc(s.ctx, func() { _ = server.Close() })
	close := func() error {
		s.Close()
		stop()
		err := server.Close()
		wg.Wait()
		done := make(chan struct{})
		go func() { s.handlers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			return errors.Join(err, errors.New("broker handlers did not stop; recovery required"))
		}
		return errors.Join(err, Cleanup(sessionID), s.Err())
	}
	return dir, close, nil
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
}
type limitedConn struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.slots })
	return err
}
func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: c, slots: l.slots}, nil
		default:
			_ = c.Close()
		}
	}
}
