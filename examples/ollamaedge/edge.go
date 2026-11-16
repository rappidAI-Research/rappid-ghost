// Package ollamaedge is an example trusted TLS/authentication front for one
// local Ollama instance. It is not a user/tenant authorization service.
package ollamaedge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/broker"
)

type Edge struct {
	client        *http.Client
	origin, model string
	token         [32]byte
	slots         chan struct{}
}

func New(origin, model, token string) (*Edge, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Port() == "" || strings.ContainsAny(u.Host, "%\\\r\n") {
		return nil, errors.New("edge requires one literal local HTTP origin and port")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || ip.To4() == nil || (!ip.IsPrivate() && !ip.IsLoopback()) || ip.IsUnspecified() || len(model) < 1 || len(model) > 128 || len(token) < 16 || len(token) > 4096 || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("invalid edge identity, model or local address")
	}
	address := net.JoinHostPort(ip.String(), u.Port())
	transport := &http.Transport{Proxy: nil, DisableCompression: true, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: 5 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 16 * 1024,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
		}}
	return &Edge{client: &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, origin: origin, model: model, token: sha256.Sum256([]byte("Bearer " + token)), slots: make(chan struct{}, 4)}, nil
}

func (e *Edge) Close() { e.client.CloseIdleConnections() }

func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	provided := sha256.Sum256([]byte(r.Header.Get("Authorization")))
	if r.TLS == nil || len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare(provided[:], e.token[:]) != 1 {
		http.Error(w, "authentication required", 401)
		return
	}
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	default:
		http.Error(w, "edge busy", 429)
		return
	}
	kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if r.Method != "POST" || r.URL.Path != "/api/chat" || r.URL.IsAbs() || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.Header.Get("Origin") != "" || r.Header.Get("Content-Encoding") != "" || err != nil || kind != "application/json" {
		http.Error(w, "unsupported model route", 400)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, broker.MaxRequestBytes+1))
	if err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	// The example independently caps generation at 64 tokens. A deployed
	// enterprise edge must select and review its own finite service ceiling.
	data, _, err = broker.NormalizeOllamaChat(data, e.model, 64)
	if err != nil {
		http.Error(w, "unqualified model request", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	call, err := http.NewRequestWithContext(ctx, "POST", e.origin+"/api/chat", bytes.NewReader(data))
	if err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	call.Header.Set("Content-Type", "application/json") // Never forward edge credentials/cookies.
	response, err := e.client.Do(call)
	if err != nil {
		http.Error(w, "model unavailable", 502)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		http.Error(w, "model rejected request", 502)
		return
	}
	kind, _, err = mime.ParseMediaType(response.Header.Get("Content-Type"))
	data, readErr := io.ReadAll(io.LimitReader(response.Body, broker.MaxResponseBytes+1))
	if err != nil || kind != "application/json" || readErr != nil || len(data) > broker.MaxResponseBytes || ctx.Err() != nil {
		http.Error(w, "invalid model response", 502)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}
