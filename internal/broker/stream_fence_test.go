package broker

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Deterministically exercises authority changing during a blocking body read,
// before any of that read's bytes have reached the agent.
type revokeOnRead struct{ f *fixture }

func (r *revokeOnRead) Read(p []byte) (int, error) {
	r.f.revoked.Store(true)
	return copy(p, "data: UNRELEASED_SYNTHETIC_RESULT\n\n"), io.EOF
}
func (*revokeOnRead) Close() error { return nil }

func TestStreamingRechecksAuthorityAfterBodyReadBeforeRelease(t *testing.T) {
	f := setup(t, nil)
	upstream := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: &revokeOnRead{f}}
	request := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	f.s.modelResponse(context.Background(), w, request, "/v1/responses", upstream, nil)
	if strings.Contains(w.Body.String(), "UNRELEASED_SYNTHETIC_RESULT") {
		t.Fatal("stream released bytes obtained after revocation")
	}
	if len(f.events) != 0 {
		t.Fatal("revoked stream recorded a successful completion")
	}
}
