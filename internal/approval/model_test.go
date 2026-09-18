package approval

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type handlerFunc func(context.Context, Request) (Response, error)

func (f handlerFunc) Decide(ctx context.Context, request Request) (Response, error) {
	return f(ctx, request)
}

func approvalRequest(id, session, host string) Request {
	return Request{ID: id, SessionID: session, Scheme: "https", Host: host, Port: 443, Method: "CONNECT", Reason: "test"}
}

func TestAllowOnceIsConsumedByExactlyOneRequest(t *testing.T) {
	var calls atomic.Int32
	controller, err := NewController("session-a", handlerFunc(func(context.Context, Request) (Response, error) {
		if calls.Add(1) == 1 {
			return Response{Scope: AllowOnce}, nil
		}
		return Response{Scope: Deny}, nil
	}), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	first := controller.Resolve(context.Background(), approvalRequest("request-1", "session-a", "api.example.com"))
	second := controller.Resolve(context.Background(), approvalRequest("request-2", "session-a", "api.example.com"))
	if !first.Granted || first.Scope != AllowOnce || second.Granted || calls.Load() != 2 {
		t.Fatalf("resolutions = %#v, %#v; calls=%d", first, second, calls.Load())
	}
}

func TestSessionApprovalIsExactAndSessionLocal(t *testing.T) {
	var calls atomic.Int32
	handler := handlerFunc(func(context.Context, Request) (Response, error) {
		calls.Add(1)
		return Response{Scope: AllowSession}, nil
	})
	first, _ := NewController("session-a", handler, time.Second)
	other, _ := NewController("session-b", nil, time.Second)
	if resolution := first.Resolve(context.Background(), approvalRequest("a1", "session-a", "api.example.com")); !resolution.Granted || resolution.Source != SourceUser {
		t.Fatalf("first resolution = %#v", resolution)
	}
	if resolution := first.Resolve(context.Background(), approvalRequest("a2", "session-a", "api.example.com")); !resolution.Granted || resolution.Source != SourceSessionApproval {
		t.Fatalf("cached resolution = %#v", resolution)
	}
	if resolution := first.Resolve(context.Background(), approvalRequest("a3", "session-a", "other.example.com")); !resolution.Granted || resolution.Source != SourceUser {
		t.Fatalf("different destination resolution = %#v", resolution)
	}
	differentMethod := approvalRequest("a4", "session-a", "api.example.com")
	differentMethod.Scheme = "http"
	differentMethod.Port = 80
	differentMethod.Method = "POST"
	if resolution := first.Resolve(context.Background(), differentMethod); !resolution.Granted || resolution.Source != SourceUser {
		t.Fatalf("different action resolution = %#v", resolution)
	}
	if calls.Load() != 3 {
		t.Fatalf("handler calls = %d, want 3 exact scopes", calls.Load())
	}
	if resolution := other.Resolve(context.Background(), approvalRequest("b1", "session-b", "api.example.com")); resolution.Granted || resolution.Reason != "approval_unavailable" {
		t.Fatalf("other-session resolution = %#v", resolution)
	}
	if resolution := first.Resolve(context.Background(), approvalRequest("bad", "session-b", "api.example.com")); resolution.Granted || resolution.Reason != "session_mismatch" {
		t.Fatalf("cross-session resolution = %#v", resolution)
	}
}

func TestUnavailableTimeoutAndMalformedResponsesFailClosed(t *testing.T) {
	unavailable, _ := NewController("session", nil, time.Second)
	if result := unavailable.Resolve(context.Background(), approvalRequest("one", "session", "api.example.com")); result.Granted || result.EventKind() != Unavailable {
		t.Fatalf("unavailable result = %#v", result)
	}

	malformed, _ := NewController("session", handlerFunc(func(context.Context, Request) (Response, error) {
		return Response{Scope: "EVERYTHING"}, nil
	}), time.Second)
	if result := malformed.Resolve(context.Background(), approvalRequest("two", "session", "api.example.com")); result.Granted || result.Source != SourceAutomatic || result.Reason != "malformed_response" || result.EventKind() != Unavailable {
		t.Fatalf("malformed result = %#v", result)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if result := malformed.Resolve(canceled, approvalRequest("canceled", "session", "api.example.com")); result.Granted || result.Source != SourceAutomatic {
		t.Fatalf("canceled result = %#v", result)
	}

	blocked := make(chan struct{})
	timed, _ := NewController("session", handlerFunc(func(context.Context, Request) (Response, error) {
		<-blocked
		return Response{Scope: AllowOnce}, nil
	}), 20*time.Millisecond)
	started := time.Now()
	result := timed.Resolve(context.Background(), approvalRequest("three", "session", "api.example.com"))
	close(blocked)
	if result.Granted || result.EventKind() != Expired || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("timeout result = %#v after %s", result, time.Since(started))
	}
}

func TestConcurrentRequestsCannotCrossAuthorize(t *testing.T) {
	controller, _ := NewController("session", handlerFunc(func(_ context.Context, request Request) (Response, error) {
		if request.Host == "one.example.com" {
			return Response{Scope: AllowOnce}, nil
		}
		return Response{Scope: Deny}, nil
	}), time.Second)
	results := make(map[string]Resolution)
	var mu sync.Mutex
	var wait sync.WaitGroup
	for _, host := range []string{"one.example.com", "two.example.com"} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result := controller.Resolve(context.Background(), approvalRequest(host, "session", host))
			mu.Lock()
			results[host] = result
			mu.Unlock()
		}()
	}
	wait.Wait()
	if !results["one.example.com"].Granted || results["two.example.com"].Granted {
		t.Fatalf("concurrent resolutions = %#v", results)
	}
}

func TestHandlerFailureFailsClosed(t *testing.T) {
	controller, _ := NewController("session", handlerFunc(func(context.Context, Request) (Response, error) {
		return Response{}, errors.New("controlled failure")
	}), time.Second)
	if result := controller.Resolve(context.Background(), approvalRequest("one", "session", "api.example.com")); result.Granted || result.Reason != "approval_unavailable" {
		t.Fatalf("failure result = %#v", result)
	}
}
