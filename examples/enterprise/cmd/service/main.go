// Explicit local synthetic application service. This is trusted application
// code, not a host execution mode for the untrusted agent.
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/rappidAI-research/rappid-ghost/examples/enterprise"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cert := flag.String("cert", "", "explicit TLS certificate")
	key := flag.String("key", "", "explicit TLS key")
	listen := flag.String("listen", "127.0.0.1:9443", "loopback address only")
	flag.Parse()
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		fmt.Fprintln(os.Stderr, "synthetic service requires loopback TLS address")
		os.Exit(1)
	}
	token := os.Getenv("GHOST_DEMO_EMPLOYEE_TOKEN")
	if len(token) < 32 {
		fmt.Fprintln(os.Stderr, "set a synthetic GHOST_DEMO_EMPLOYEE_TOKEN of at least 32 bytes")
		os.Exit(1)
	}
	app := enterprise.New(token)
	server := &http.Server{Addr: *listen, Handler: app, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 * 1024}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	revocation := make(chan os.Signal, 1)
	signal.Notify(revocation, syscall.SIGHUP)
	defer signal.Stop(revocation)
	go func() {
		for {
			select {
			case <-ctx.Done():
				shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				server.Shutdown(shutdown)
				cancel()
				return
			case <-revocation:
				app.Revoke()
			}
		}
	}()
	if err = server.ListenAndServeTLS(*cert, *key); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "synthetic service failed:", err)
		os.Exit(1)
	}
}
