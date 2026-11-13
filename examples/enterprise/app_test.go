package enterprise

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApplicationOwnsEmployeeTenantAndRevocationAuthorization(t *testing.T) {
	app := New("synthetic-employee-A-token")
	call := func(body, token string) int {
		r := httptest.NewRequest("POST", "/ghost/tools/call", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		return w.Code
	}
	for _, resource := range []string{"case_B", "tenant_B_case_C"} {
		if call(`{"id":"x","name":"documents.read","effect":"read","arguments":{"record_id":"`+resource+`"}}`, app.token) != 403 {
			t.Fatal("foreign authorization accepted")
		}
	}
	allowed := `{"id":"x","name":"documents.read","effect":"read","arguments":{"record_id":"case_A"}}`
	if call(allowed, "untrusted-agent-token") != 401 || call(allowed, app.token) != 200 {
		t.Fatal("employee identity boundary failed")
	}
	if call(`{"id":"x","name":"documents.read","effect":"read","arguments":{"record_id":"case_A","tenant":"tenant_A"}}`, app.token) != 400 {
		t.Fatal("agent supplied authorization metadata accepted")
	}
	app.Revoke()
	if call(allowed, app.token) != 403 {
		t.Fatal("revocation ignored")
	}
}
