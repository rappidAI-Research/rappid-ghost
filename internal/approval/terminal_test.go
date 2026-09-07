package approval

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTerminalResponseParsing(t *testing.T) {
	for input, want := range map[string]Scope{
		"a": AllowOnce, "ALLOW": AllowOnce, "s": AllowSession, "allow for session": AllowSession,
		"": Deny, "d": Deny, "unexpected": "",
	} {
		if got := parseTerminalResponse(input).Scope; got != want {
			t.Errorf("parseTerminalResponse(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestTerminalMuxSeparatesApprovalFromAgentInput(t *testing.T) {
	inputReader, inputWriter := io.Pipe()
	output := &notifyingBuffer{ready: make(chan struct{})}
	mux := NewTerminalMux(inputReader, output)
	defer mux.Close()

	result := make(chan Response, 1)
	go func() {
		response, _ := mux.Decide(context.Background(), Request{
			ID: "one", SessionID: "session", Scheme: "https", Host: "api.example.com", Port: 443,
			Method: "CONNECT", Reason: "destination requires approval", Timeout: time.Second,
			Context: SecurityContext{SuspiciousInstructions: true},
		})
		result <- response
	}()
	select {
	case <-output.ready:
	case <-time.After(time.Second):
		t.Fatal("approval prompt was not rendered")
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := inputWriter.Write([]byte("a\nagent-input\n"))
		writeDone <- err
	}()
	if response := <-result; response.Scope != AllowOnce {
		t.Fatalf("approval response = %#v", response)
	}
	agent := make([]byte, len("agent-input\n"))
	if _, err := io.ReadFull(mux.AgentInput(), agent); err != nil || string(agent) != "agent-input\n" {
		t.Fatalf("agent input = %q, %v", agent, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if text := output.String(); !strings.Contains(text, "Ghost paused a sensitive request") || !strings.Contains(text, "Suspicious repository instructions") {
		t.Fatalf("prompt output = %q", text)
	}
}

func TestBuffersAreNotTreatedAsInteractiveTerminal(t *testing.T) {
	if InteractiveAvailable(bytes.NewBuffer(nil), bytes.NewBuffer(nil)) {
		t.Fatal("ordinary buffers were treated as an interactive terminal")
	}
}

type notifyingBuffer struct {
	mu    sync.Mutex
	data  bytes.Buffer
	ready chan struct{}
	once  sync.Once
}

func (b *notifyingBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, err := b.data.Write(value)
	if strings.Contains(b.data.String(), "Choice:") {
		b.once.Do(func() { close(b.ready) })
	}
	return n, err
}

func (b *notifyingBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.String()
}
