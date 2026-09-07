package approval

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

type promptCall struct {
	ctx      context.Context
	request  Request
	response chan promptResult
}

type promptResult struct {
	response Response
	err      error
}

type readResult struct {
	value    byte
	hasValue bool
	err      error
}

// TerminalMux keeps Ghost as the sole reader of an interactive terminal. It
// normally forwards bytes to the agent, but temporarily routes one bounded
// line to a pending approval prompt. This avoids concurrent reads by Docker
// and the approval subsystem.
type TerminalMux struct {
	input  io.Reader
	output io.Writer
	agent  *io.PipeReader
	feed   *io.PipeWriter
	calls  chan promptCall
	stop   chan struct{}

	closeOnce sync.Once
}

func NewTerminalMux(input io.Reader, output io.Writer) *TerminalMux {
	agent, feed := io.Pipe()
	mux := &TerminalMux{
		input: input, output: output, agent: agent, feed: feed,
		calls: make(chan promptCall), stop: make(chan struct{}),
	}
	go mux.run()
	return mux
}

func InteractiveAvailable(input io.Reader, output io.Writer) bool {
	in, inputOK := input.(*os.File)
	out, outputOK := output.(*os.File)
	if !inputOK || !outputOK {
		return false
	}
	inInfo, inErr := in.Stat()
	outInfo, outErr := out.Stat()
	return inErr == nil && outErr == nil && inInfo.Mode()&os.ModeCharDevice != 0 && outInfo.Mode()&os.ModeCharDevice != 0
}

func (m *TerminalMux) AgentInput() io.Reader { return m.agent }

func (m *TerminalMux) Decide(ctx context.Context, request Request) (Response, error) {
	call := promptCall{ctx: ctx, request: request, response: make(chan promptResult, 1)}
	select {
	case m.calls <- call:
	case <-ctx.Done():
		return Response{}, ctx.Err()
	case <-m.stop:
		return Response{}, errors.New("approval terminal is closed")
	}
	select {
	case result := <-call.response:
		return result.response, result.err
	case <-ctx.Done():
		return Response{}, ctx.Err()
	case <-m.stop:
		return Response{}, errors.New("approval terminal is closed")
	}
}

func (m *TerminalMux) Close() error {
	var err error
	m.closeOnce.Do(func() {
		close(m.stop)
		err = m.feed.Close()
		_ = m.agent.Close()
	})
	return err
}

func (m *TerminalMux) run() {
	reads := make(chan readResult)
	go func() {
		buffer := make([]byte, 1)
		for {
			n, err := m.input.Read(buffer)
			result := readResult{err: err}
			if n == 1 {
				result.value, result.hasValue = buffer[0], true
			}
			select {
			case reads <- result:
			case <-m.stop:
				return
			}
			if err != nil {
				return
			}
		}
	}()

	for {
		select {
		case call := <-m.calls:
			m.prompt(reads, call)
		case result := <-reads:
			if result.hasValue {
				if _, err := m.feed.Write([]byte{result.value}); err != nil {
					return
				}
			}
			if result.err != nil {
				_ = m.feed.CloseWithError(result.err)
				return
			}
		case <-m.stop:
			return
		}
	}
}

func (m *TerminalMux) prompt(reads <-chan readResult, call promptCall) {
	fmt.Fprintln(m.output)
	fmt.Fprintln(m.output, "Ghost paused a sensitive request.")
	fmt.Fprintf(m.output, "Destination: %s\n", call.request.Resource())
	fmt.Fprintf(m.output, "Reason: %s\n", call.request.Reason)
	if call.request.Context.SuspiciousInstructions {
		fmt.Fprintln(m.output, "Security context: Suspicious repository instructions were observed earlier in this session.")
	}
	fmt.Fprintln(m.output, "[A] Allow once  [S] Allow for this session  [D] Deny")
	fmt.Fprintf(m.output, "Default: Deny (timeout %s)\nChoice: ", call.request.Timeout)

	var line strings.Builder
	for line.Len() <= 32 {
		select {
		case result := <-reads:
			if result.hasValue && (result.value == '\n' || result.value == '\r') {
				fmt.Fprintln(m.output)
				call.response <- promptResult{response: parseTerminalResponse(line.String())}
				return
			}
			if result.hasValue {
				line.WriteByte(result.value)
			}
			if result.err != nil {
				fmt.Fprintln(m.output, "\nApproval unavailable; denied.")
				call.response <- promptResult{err: result.err}
				return
			}
		case <-call.ctx.Done():
			fmt.Fprintln(m.output, "\nApproval timed out; denied.")
			call.response <- promptResult{err: call.ctx.Err()}
			return
		case <-m.stop:
			call.response <- promptResult{err: errors.New("approval terminal is closed")}
			return
		}
	}
	fmt.Fprintln(m.output, "\nMalformed approval response; denied.")
	call.response <- promptResult{response: Response{}}
}

func parseTerminalResponse(value string) Response {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "a", "allow", "allow once":
		return Response{Scope: AllowOnce}
	case "s", "session", "allow session", "allow for session":
		return Response{Scope: AllowSession}
	case "", "d", "deny":
		return Response{Scope: Deny}
	default:
		return Response{}
	}
}
