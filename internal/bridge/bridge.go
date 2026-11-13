// Package bridge provides the guest-side loopback HTTP interface to one
// session's Unix socket. It carries no upstream credentials or policy.
package bridge

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/broker"
	"golang.org/x/sys/unix"
)

const Address = "127.0.0.1:17871"
const Socket = "/run/ghost-broker/broker.sock"
const Executable = "/run/ghost-helper"

// Run is an internal guest entrypoint, not a host agent execution mode. The
// runtime must bind this very executable read-only into its read-only root.
func Run(ctx context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(argv) < 1 || !guestBoundary() {
		io.WriteString(stderr, "ghost: broker helper requires the isolated Ghost guest boundary\n")
		return 1
	}
	if err := protectBridge(); err != nil {
		io.WriteString(stderr, "ghost: broker bridge process protection unavailable\n")
		return 1
	}
	listener, err := net.Listen("tcp4", Address)
	if err != nil {
		io.WriteString(stderr, "ghost: broker loopback listener unavailable\n")
		return 1
	}
	transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: 5 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", Socket)
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	slots := make(chan struct{}, 4)
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 3 * time.Second, MaxHeaderBytes: 16 * 1024,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			default:
				http.Error(w, "bridge busy", 429)
				return
			}
			if r.Method != "POST" || r.Host != Address || r.Header.Get("Origin") != "" || r.URL.IsAbs() || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.ContentLength > broker.MaxRequestBytes {
				http.Error(w, "invalid bridge request", 400)
				return
			}
			switch r.URL.Path {
			case "/v1/responses", "/v1/chat/completions", "/ghost/tools/call", "/mcp":
			default:
				http.Error(w, "unregistered route", 404)
				return
			}
			callCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			stop := context.AfterFunc(ctx, cancel)
			defer stop()
			request, err := http.NewRequestWithContext(callCtx, "POST", "http://ghost-broker"+r.URL.Path, http.MaxBytesReader(w, r.Body, broker.MaxRequestBytes))
			if err != nil {
				http.Error(w, "invalid request", 400)
				return
			}
			for _, key := range []string{"Content-Type", "Accept", "MCP-Protocol-Version", "Mcp-Method", "Mcp-Name"} {
				if values := r.Header.Values(key); len(values) == 1 {
					request.Header.Set(key, values[0])
				}
			}
			response, err := client.Do(request)
			if err != nil {
				http.Error(w, "Ghost session broker unavailable", 503)
				return
			}
			defer response.Body.Close()
			w.Header().Set("Content-Type", response.Header.Get("Content-Type"))
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(response.StatusCode)
			buffer := make([]byte, 16*1024)
			remaining := int64(broker.MaxResponseBytes)
			for {
				n, readErr := response.Body.Read(buffer)
				if int64(n) > remaining {
					panic(http.ErrAbortHandler)
				}
				remaining -= int64(n)
				if n > 0 {
					if _, err = w.Write(buffer[:n]); err != nil {
						return
					}
					if flush, ok := w.(http.Flusher); ok {
						flush.Flush()
					}
				}
				if readErr == io.EOF {
					return
				}
				if readErr != nil {
					panic(http.ErrAbortHandler)
				}
			}
		})}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer server.Close()
	command := exec.CommandContext(ctx, Executable, append([]string{"_broker-agent"}, argv...)...)
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	command.Env = os.Environ() // only the explicitly constructed guest environment
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	}
	command.WaitDelay = 2 * time.Second
	err = command.Run()
	select {
	case serveErr := <-done:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			io.WriteString(stderr, "ghost: broker bridge failed\n")
			return 1
		}
	default:
	}
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	io.WriteString(stderr, "ghost: configured guest agent could not start\n")
	return 1
}
func guestBoundary() bool {
	var stat unix.Statfs_t
	if unix.Statfs("/", &stat) != nil || stat.Flags&unix.ST_RDONLY == 0 {
		return false
	}
	self, err := os.Stat("/proc/self/exe")
	if err != nil {
		return false
	}
	bound, err := os.Stat(Executable)
	if err != nil || !os.SameFile(self, bound) {
		return false
	}
	socket, err := os.Lstat(Socket)
	return err == nil && socket.Mode()&os.ModeSocket != 0 && socket.Mode().Perm() == 0600
}

// Environment contains guest-only endpoint hints. The dummy API key is not a
// credential and is ignored by the host broker, which supplies its own identity.
func Environment(model string) []string {
	values := []string{"GHOST_BROKER_URL=http://" + Address, "GHOST_BROKER_BRIDGE=1"}
	if model != "" {
		values = append(values, "OPENAI_BASE_URL=http://"+Address+"/v1", "OPENAI_API_KEY=ghost-session", "GHOST_MODEL="+model)
	}
	return values
}
