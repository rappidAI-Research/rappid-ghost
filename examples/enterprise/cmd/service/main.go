// Explicit local synthetic application service. This is trusted application
// code, not a host execution mode for the untrusted agent.
package main

import (
	"context"
	"encoding/json"
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
	ready := flag.String("ready", "", "optional new private file containing the bound TLS origin")
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
	if second := os.Getenv("GHOST_DEMO_SECOND_TOKEN"); second != "" {
		if len(second) < 32 || second == token {
			fmt.Fprintln(os.Stderr, "provide a distinct synthetic second credential of at least 32 bytes")
			os.Exit(1)
		}
		app, err = enterprise.NewForEmployees(map[string]enterprise.Assignment{
			token:  {Employee: "employee_A", Tenant: "tenant_A", Role: "caseworker", Records: []string{"case_A"}},
			second: {Employee: "employee_B", Tenant: "tenant_B", Role: "reviewer", Records: []string{"tenant_B_case_C"}},
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid trusted demo assignments")
			os.Exit(1)
		}
	}
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
				app.RevokeEmployee("employee_A", "tenant_A")
				fmt.Fprintln(os.Stderr, "SYNTHETIC_PRIMARY_REVOKED")
			}
		}
	}()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot bind demo service")
		os.Exit(1)
	}
	defer listener.Close()
	if *ready != "" {
		file, createErr := os.OpenFile(*ready, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil {
			fmt.Fprintln(os.Stderr, "cannot create private readiness file")
			os.Exit(1)
		}
		encodeErr := json.NewEncoder(file).Encode(map[string]string{"url": "https://" + listener.Addr().String()})
		closeErr := file.Close()
		if encodeErr != nil || closeErr != nil {
			fmt.Fprintln(os.Stderr, "cannot publish demo readiness")
			os.Exit(1)
		}
	}
	if err = server.ServeTLS(listener, *cert, *key); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "synthetic service failed:", err)
		os.Exit(1)
	}
}
