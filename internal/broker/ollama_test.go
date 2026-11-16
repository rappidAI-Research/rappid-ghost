package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const ollamaInput = `{"model":"ghost-fixture","messages":[{"role":"user","content":"SYNTHETIC_PRIVATE_PROMPT"}],"stream":false}`
const ollamaOutput = `{"model":"ghost-fixture","created_at":"2026-11-16T00:00:00Z","message":{"role":"assistant","content":"LOCAL_REPLY"},"done":true,"done_reason":"stop","eval_count":5,"prompt_eval_cached_count":0}`

func restartFixture(t *testing.T, f *fixture) {
	t.Helper()
	f.s.Close()
	var err error
	f.s, err = New(context.Background(), f.cfg, f.s.options)
	if err != nil {
		t.Fatal(err)
	}
}

func ollamaFixture(t *testing.T, handler http.HandlerFunc) *fixture {
	t.Helper()
	if handler == nil {
		handler = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(ollamaOutput))
		}
	}
	f := setup(t, handler)
	f.cfg.Model.Protocol = ProtocolOllama
	f.cfg.Model.MaxOutputTokens = 64
	restartFixture(t, f)
	return f
}

func TestOllamaNativeProtocolPinsModelAuthAndFiniteOptions(t *testing.T) {
	f := ollamaFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var v ollamaChat
		if json.NewDecoder(r.Body).Decode(&v) != nil || v.Options == nil || v.Options.NumPredict == nil || *v.Options.NumPredict != 64 || v.Options.NumCtx == nil || *v.Options.NumCtx != 2048 || v.Stream || v.KeepAlive != 0 || v.Model != "ghost-fixture" || r.URL.Path != "/api/chat" || r.Header.Get("Authorization") != "Bearer HOST_ONLY_SYNTHETIC_CREDENTIAL" || r.Header.Get("Cookie") != "" {
			t.Error("upstream did not receive the bounded native contract")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(ollamaOutput))
	})
	w := request(f.s, "/api/chat", ollamaInput)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "LOCAL_REPLY") || f.calls.Load() != 1 {
		t.Fatalf("response %d: %s", w.Code, w.Body.String())
	}
	audit, _ := json.Marshal(f.events)
	if bytes.Contains(audit, []byte("SYNTHETIC_PRIVATE_PROMPT")) || bytes.Contains(audit, []byte("LOCAL_REPLY")) || bytes.Contains(audit, []byte("HOST_ONLY_SYNTHETIC_CREDENTIAL")) {
		t.Fatal("sensitive content reached durable audit")
	}
}

func TestOllamaRejectsUnqualifiedInputsWithoutUpstreamAccess(t *testing.T) {
	for name, body := range map[string]string{
		"different model":  strings.Replace(ollamaInput, "ghost-fixture", "foreign-model", 1),
		"stream":           strings.Replace(ollamaInput, "false", "true", 1),
		"image":            `{"model":"ghost-fixture","messages":[{"role":"user","content":"x","images":["remote"]}]}`,
		"tool":             `{"model":"ghost-fixture","messages":[{"role":"tool","content":"x"}]}`,
		"tools":            strings.TrimSuffix(ollamaInput, "}") + `,"tools":[{"type":"web_search"}]}`,
		"remote":           strings.TrimSuffix(ollamaInput, "}") + `,"server_url":"http://internal.invalid"}`,
		"unlimited":        strings.TrimSuffix(ollamaInput, "}") + `,"options":{"num_predict":-1}}`,
		"output budget":    strings.TrimSuffix(ollamaInput, "}") + `,"options":{"num_predict":65}}`,
		"context budget":   strings.TrimSuffix(ollamaInput, "}") + `,"options":{"num_ctx":8192}}`,
		"unknown option":   strings.TrimSuffix(ollamaInput, "}") + `,"options":{"num_gpu":100}}`,
		"retention":        strings.TrimSuffix(ollamaInput, "}") + `,"keep_alive":600}`,
		"foreign identity": strings.TrimSuffix(ollamaInput, "}") + `,"tenant":"tenant_B"}`,
		"missing messages": `{"model":"ghost-fixture"}`,
		"null content":     `{"model":"ghost-fixture","messages":[{"role":"user","content":null}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := ollamaFixture(t, nil)
			if request(f.s, "/api/chat", body).Code == 200 || f.calls.Load() != 0 {
				t.Fatal("denied input reached model")
			}
		})
	}
}

func TestModelProtocolsAndManagementRoutesCannotBeMixed(t *testing.T) {
	f := ollamaFixture(t, nil)
	for _, path := range []string{"/v1/responses", "/v1/chat/completions", "/api/pull", "/api/create", "/api/delete", "/api/tags", "/api/generate"} {
		if request(f.s, path, ollamaInput).Code == 200 {
			t.Fatal("ungranted protocol route accepted")
		}
	}
	if f.calls.Load() != 0 {
		t.Fatal("ungranted route reached service")
	}
	openai := setup(t, nil)
	if request(openai.s, "/api/chat", ollamaInput).Code != 403 || openai.calls.Load() != 0 {
		t.Fatal("OpenAI grant accepted native Ollama")
	}
}

func TestOllamaRejectsUnexpectedResponseSemantics(t *testing.T) {
	for _, body := range []string{
		`{}`, strings.Replace(ollamaOutput, "ghost-fixture", "foreign", 1), strings.Replace(ollamaOutput, `"done":true`, `"done":false`, 1),
		strings.Replace(ollamaOutput, `"eval_count":5`, `"eval_count":65`, 1),
		strings.Replace(ollamaOutput, `"content":"LOCAL_REPLY"`, `"content":"LOCAL_REPLY","tool_calls":[{}]`, 1),
	} {
		t.Run(body, func(t *testing.T) {
			f := ollamaFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			})
			if w := request(f.s, "/api/chat", ollamaInput); w.Code != 502 || strings.Contains(w.Body.String(), "LOCAL_REPLY") {
				t.Fatal("invalid model result released")
			}
		})
	}
}
