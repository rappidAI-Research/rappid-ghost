package approval

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSessionGrantDoesNotWidenOneScopeDimension(t *testing.T) {
	for _, dimension := range []string{"host", "method", "scheme", "port", "session"} {
		t.Run(dimension, func(t *testing.T) {
			var calls atomic.Int32
			c, _ := NewController("s", handlerFunc(func(context.Context, Request) (Response, error) {
				if calls.Add(1) == 1 {
					return Response{Scope: AllowSession}, nil
				}
				return Response{Scope: Deny}, nil
			}), time.Second)
			initial := approvalRequest("first", "s", "api.example.com")
			if !c.Resolve(context.Background(), initial).Granted {
				t.Fatal("initial grant missing")
			}
			next := initial
			next.ID = "second"
			switch dimension {
			case "host":
				next.Host = "sub.api.example.com"
			case "method":
				next.Method = "GET"
			case "scheme":
				next.Scheme = "http"
			case "port":
				next.Port = 8443
			case "session":
				next.SessionID = "other"
			}
			if r := c.Resolve(context.Background(), next); r.Granted {
				t.Fatalf("grant widened %s: %+v", dimension, r)
			}
		})
	}
}

func TestConcurrentIdenticalRequestsConsumeOnlyOneAllowOnce(t *testing.T) {
	var calls atomic.Int32
	c, _ := NewController("s", handlerFunc(func(context.Context, Request) (Response, error) {
		if calls.Add(1) == 1 {
			return Response{Scope: AllowOnce}, nil
		}
		return Response{Scope: Deny}, nil
	}), time.Second)
	start := make(chan struct{})
	var wg sync.WaitGroup
	var granted atomic.Int32
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r := c.Resolve(context.Background(), approvalRequest(fmt.Sprint(i), "s", "api.example.com"))
			if r.Granted {
				granted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if calls.Load() != 16 || granted.Load() != 1 {
		t.Fatalf("calls=%d granted=%d", calls.Load(), granted.Load())
	}
}

func TestCanceledLateSessionDecisionCannotCreateGrant(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	c, _ := NewController("s", handlerFunc(func(context.Context, Request) (Response, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
			return Response{Scope: AllowSession}, nil
		}
		return Response{Scope: Deny}, nil
	}), time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Resolution, 1)
	go func() { done <- c.Resolve(ctx, approvalRequest("first", "s", "api.example.com")) }()
	<-entered
	cancel()
	close(release)
	if r := <-done; r.Granted {
		t.Fatal("canceled operation granted")
	}
	if r := c.Resolve(context.Background(), approvalRequest("second", "s", "api.example.com")); r.Granted || calls.Load() != 2 {
		t.Fatal("late grant leaked")
	}
}
