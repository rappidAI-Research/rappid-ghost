package broker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPerToolBudgetIsAtomicAcrossParallelUniqueCalls(t *testing.T) {
	f := setup(t, nil)
	f.cfg.Tools[0].MaxCalls = 1
	restartFixture(t, f)
	var wg sync.WaitGroup
	var success atomic.Int64
	for i := range 4 {
		wg.Go(func() {
			body := fmt.Sprintf(`{"id":"call%d","name":"documents.read","arguments":{"record_id":"case_A"}}`, i)
			if request(f.s, "/ghost/tools/call", body).Code == 200 {
				success.Add(1)
			}
		})
	}
	wg.Wait()
	if success.Load() != 1 || f.calls.Load() != 1 {
		t.Fatalf("success=%d effects=%d", success.Load(), f.calls.Load())
	}
	if request(f.s, "/ghost/tools/call", `{"id":"callLater","name":"documents.read","arguments":{"record_id":"case_A"}}`).Code != 429 {
		t.Fatal("tool budget reset")
	}
}

func TestToolResultAndTimeCeilings(t *testing.T) {
	t.Run("bytes", func(t *testing.T) {
		f := setup(t, nil)
		f.cfg.Tools[0].MaxResultBytes = 2
		restartFixture(t, f)
		w := request(f.s, "/ghost/tools/call", `{"id":"callA","name":"documents.read","arguments":{"record_id":"case_A"}}`)
		if w.Code != 502 || strings.Contains(w.Body.String(), "synthetic-only") {
			t.Fatal("oversized tool result released")
		}
	})
	t.Run("deadline", func(t *testing.T) {
		cancelled := make(chan struct{})
		f := setup(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			select {
			case <-r.Context().Done():
				close(cancelled)
			case <-time.After(2 * time.Second):
			}
		})
		f.cfg.Tools[0].TimeoutMillis = 50
		restartFixture(t, f)
		start := time.Now()
		if request(f.s, "/ghost/tools/call", `{"id":"callA","name":"documents.read","arguments":{"record_id":"case_A"}}`).Code == 200 || time.Since(start) > 3*time.Second {
			t.Fatal("tool deadline not enforced")
		}
		select {
		case <-cancelled:
		case <-time.After(3 * time.Second):
			t.Fatal("upstream did not observe cancellation")
		}
	})
}

func TestRevocationDuringCompletionAuditPreventsBufferedResultRelease(t *testing.T) {
	for _, path := range []string{"/ghost/tools/call", "/v1/chat/completions", "/api/chat"} {
		t.Run(path, func(t *testing.T) {
			var f *fixture
			body := `{"model":"ghost-fixture","messages":[{"role":"user","content":"x"}]}`
			if path == "/api/chat" {
				f = ollamaFixture(t, nil)
				body = ollamaInput
			} else {
				f = setup(t, nil)
			}
			if path == "/ghost/tools/call" {
				body = `{"id":"callA","name":"documents.read","arguments":{"record_id":"case_A"}}`
			}
			original := f.s.options.Audit
			f.s.options.Audit = func(ctx context.Context, e Event) error {
				if e.Kind == "completion" {
					f.revoked.Store(true)
				}
				return original(ctx, e)
			}
			w := request(f.s, path, body)
			if w.Code == 200 || strings.Contains(w.Body.String(), "LOCAL_REPLY") || strings.Contains(w.Body.String(), "synthetic-only") {
				t.Fatal("revoked result released after completion audit")
			}
		})
	}
}

func TestBrokerContractAndToolBudgetsValidate(t *testing.T) {
	f := setup(t, nil)
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Version = 2 }, func(c *Config) { c.Model.Protocol = "unknown" },
		func(c *Config) { c.Model.Protocol = ProtocolOllama; c.Model.CredentialEnv = "" },
		func(c *Config) { c.Tools[0].MaxCalls = 513 }, func(c *Config) { c.Tools[0].TimeoutMillis = 1 }, func(c *Config) { c.Tools[0].MaxResultBytes = MaxRequestBytes + 1 },
	} {
		c := f.cfg.Snapshot()
		mutate(&c)
		if c.Validate() == nil {
			t.Fatal("invalid contract accepted")
		}
	}
	if f.cfg.Validate() != nil {
		t.Fatal("v0.5 configuration no longer valid")
	}
}
