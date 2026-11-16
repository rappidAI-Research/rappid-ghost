// A trusted example service, never an agent execution fallback.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rappidAI-research/rappid-ghost/examples/ollamaedge"
)

func run() error {
	upstream := flag.String("upstream", "", "")
	model := flag.String("model", "", "")
	cert := flag.String("cert", "", "")
	key := flag.String("key", "", "")
	ready := flag.String("ready", "", "")
	flag.Parse()
	if flag.NArg() != 0 || *cert == "" || *key == "" || *ready == "" {
		return errors.New("missing explicit edge configuration")
	}
	edge, err := ollamaedge.New(*upstream, *model, os.Getenv("GHOST_OLLAMA_EDGE_TOKEN"))
	if err != nil {
		return err
	}
	defer edge.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{Handler: edge, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 3 * time.Second, MaxHeaderBytes: 16 * 1024, ErrorLog: log.New(os.Stderr, "edge: ", 0)}
	file, err := os.OpenFile(*ready, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	err = json.NewEncoder(file).Encode(map[string]string{"url": "https://" + listener.Addr().String()})
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err = server.ServeTLS(listener, *cert, *key)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func main() {
	if err := run(); err != nil {
		log.Print("local model edge failed: ", err)
		os.Exit(1)
	}
}
