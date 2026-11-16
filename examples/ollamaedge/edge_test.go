package ollamaedge

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAuthenticatedTLSModelBindingAndCredentialSeparation(t *testing.T) {
	var calls atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		data, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/api/chat" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || !strings.Contains(string(data), `"num_predict":64`) {
			t.Error("edge forwarded authority or lost finite generation")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":"synthetic"}`))
	}))
	defer backend.Close()
	edge, err := New(backend.URL, "local-model", "SYNTHETIC_EDGE_CREDENTIAL")
	if err != nil {
		t.Fatal(err)
	}
	defer edge.Close()
	server := httptest.NewTLSServer(edge)
	defer server.Close()
	for _, tc := range []struct {
		token, path, body string
		status            int
	}{
		{"", "/api/chat", `{}`, 401},
		{"wrong", "/api/chat", `{}`, 401},
		{"SYNTHETIC_EDGE_CREDENTIAL", "/api/pull", `{}`, 400},
		{"SYNTHETIC_EDGE_CREDENTIAL", "/api/chat", `{"model":"foreign","messages":[{"role":"user","content":"x"}]}`, 400},
		{"SYNTHETIC_EDGE_CREDENTIAL", "/api/chat", `{"model":"local-model","messages":[{"role":"user","content":"x","images":["secret"]}]}`, 400},
		{"SYNTHETIC_EDGE_CREDENTIAL", "/api/chat", `{"model":"local-model","messages":[{"role":"user","content":"x"}],"options":{"num_predict":-1}}`, 400},
		{"SYNTHETIC_EDGE_CREDENTIAL", "/api/chat", `{"model":"local-model","messages":[{"role":"user","content":"x"}],"stream":false}`, 200},
	} {
		r, _ := http.NewRequest("POST", server.URL+tc.path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Cookie", "private")
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != tc.status {
			t.Fatalf("status %d expected %d", response.StatusCode, tc.status)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("denied calls reached local model: %d", calls.Load())
	}
}

func TestEdgeRejectsRedirectsAndUnboundUpstreams(t *testing.T) {
	for _, origin := range []string{"http://example.com:11434", "http://0.0.0.0:11434", "https://127.0.0.1:11434", "http://127.0.0.1:11434/api/chat", "http://user:pass@127.0.0.1:11434", "http://169.254.169.254:80", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:11434?"} {
		if e, err := New(origin, "local-model", "SYNTHETIC_EDGE_CREDENTIAL"); err == nil {
			e.Close()
			t.Fatal("unbound upstream accepted")
		}
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://127.0.0.1:1/private")
		w.WriteHeader(302)
	}))
	defer backend.Close()
	edge, err := New(backend.URL, "local-model", "SYNTHETIC_EDGE_CREDENTIAL")
	if err != nil {
		t.Fatal(err)
	}
	defer edge.Close()
	server := httptest.NewTLSServer(edge)
	defer server.Close()
	r, _ := http.NewRequest("POST", server.URL+"/api/chat", strings.NewReader(`{"model":"local-model","messages":[{"role":"user","content":"x"}]}`))
	r.Header.Set("Authorization", "Bearer SYNTHETIC_EDGE_CREDENTIAL")
	r.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 502 {
		t.Fatal("redirect accepted")
	}
}
