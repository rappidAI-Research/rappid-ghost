package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/broker"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
)

func TestEvidenceBudgetKeepsTerminalHeadroomAndSurvivesConnectionReplacement(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "literal?#_pragma=foreign_keys(0).db")
	s, err := OpenWithOptions(ctx, path, Options{MaxDatabaseMiB: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if info, err := os.Stat(path); err != nil || info.Size() == 0 {
		t.Fatal("SQLite URI escaped the literal configured filename")
	}
	id, err := session.NewID()
	if err != nil {
		t.Fatal(err)
	}
	v := session.Session{ID: id, CreatedAt: time.Now().UTC(), Command: []string{"true"}, Runtime: "docker", Status: session.Running, SecurityState: policy.StateNormal}
	if err = s.CreateSession(ctx, v); err != nil {
		t.Fatal(err)
	}
	full := false
	for range 1024 {
		e := &events.Event{SessionID: id, Timestamp: time.Now().UTC(), Type: events.BrokerAdmission, Metadata: map[string]any{"synthetic": strings.Repeat("x", 48*1024)}}
		err = s.AddEvent(ctx, e)
		if errors.Is(err, ErrCapacity) {
			full = true
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !full {
		t.Fatal("evidence budget was not enforced")
	}
	// Actual broker admission uses the production capped SQLite writer. Full
	// evidence must prevent a valid authorized request reaching its service.
	var effects atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		effects.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":"must not release"}`))
	}))
	defer upstream.Close()
	cert := sha256.Sum256(upstream.Certificate().Raw)
	mediator, err := broker.New(ctx, broker.Config{Model: &broker.Model{Endpoint: broker.Endpoint{URL: upstream.URL, CertificateSHA256: hex.EncodeToString(cert[:])}, Name: "budget-fixture"}}, broker.Options{Check: func(context.Context) error { return nil }, Audit: func(ctx context.Context, e broker.Event) error {
		return s.AddEvent(ctx, &events.Event{SessionID: id, Timestamp: e.Time, Type: events.BrokerAdmission, Metadata: map[string]any{"operation": e.Operation, "reason": e.Reason}})
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer mediator.Close()
	request := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"budget-fixture","messages":[{"role":"user","content":"synthetic"}]}`))
	request.Host = "ghost-broker"
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	mediator.ServeHTTP(response, request)
	if response.Code != 503 || effects.Load() != 0 || mediator.Err() == nil {
		t.Fatal("evidence exhaustion did not fail closed before model access")
	}
	completed := time.Now().UTC()
	exit := 0
	v.Status = session.Failed
	v.CompletedAt = &completed
	v.ExitCode = &exit
	end := &events.Event{SessionID: id, Timestamp: completed, Type: events.SessionEnd, Metadata: map[string]any{"reason": "evidence budget exhausted"}}
	if err = s.FinalizeSession(ctx, v, end); err != nil {
		t.Fatalf("reserved terminal persistence failed: %v", err)
	}
	s.db.SetMaxIdleConns(0) // Force every following query onto a fresh connection.
	for statement, wanted := range map[string]int64{"PRAGMA foreign_keys": 1, "PRAGMA secure_delete": 1, "PRAGMA busy_timeout": 500, "PRAGMA max_page_count": 2048} {
		var actual int64
		if err = s.db.QueryRowContext(ctx, statement).Scan(&actual); err != nil || actual != wanted {
			t.Fatalf("reconnected %s=%d want=%d err=%v", statement, actual, wanted, err)
		}
	}
	var pages, size int64
	_ = s.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages)
	_ = s.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size)
	if pages*size > 8*1024*1024 {
		t.Fatal("SQLite crossed the hard main-page ceiling")
	}
	if err = s.AddEvent(ctx, &events.Event{SessionID: id, Timestamp: time.Now().UTC(), Type: events.BrokerAdmission}); !errors.Is(err, ErrCapacity) {
		t.Fatal("connection replacement reset evidence admission budget")
	}
}
