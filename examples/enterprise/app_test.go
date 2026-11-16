package enterprise

import (
	"net/http/httptest"
	"strings"
	"sync"
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

func TestMultipleEmployeeAssignmentsRemainSeparateDuringRevocation(t *testing.T) {
	a := Assignment{"employee_A", "tenant_A", "caseworker", []string{"case_A"}}
	b := Assignment{"employee_B", "tenant_B", "reviewer", []string{"tenant_B_case_C"}}
	app, err := NewForEmployees(map[string]Assignment{"token_A": a, "token_B": b})
	if err != nil {
		t.Fatal(err)
	}
	a.Records[0] = "case_B" // Caller mutation must not change a provisioned grant.
	if _, code := app.read("token_A", "case_A"); code != 200 {
		t.Fatal("assignment aliases caller storage")
	}
	for _, attempt := range []struct{ token, record string }{{"token_A", "case_B"}, {"token_A", "tenant_B_case_C"}, {"token_B", "case_A"}, {"unknown", "case_A"}} {
		if _, code := app.read(attempt.token, attempt.record); code == 200 {
			t.Fatal("identity or tenant crossed")
		}
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 16 {
				if _, code := app.read("token_B", "tenant_B_case_C"); code != 200 {
					t.Error("another employee's revocation affected authorized identity")
				}
			}
		})
	}
	app.RevokeEmployee("employee_A", "tenant_A")
	workers.Wait()
	if _, code := app.read("token_A", "case_A"); code != 403 {
		t.Fatal("primary revocation ignored")
	}
	if _, err := NewForEmployees(map[string]Assignment{"bad": {"employee_A", "tenant_A", "admin", []string{"tenant_B_case_C"}}}); err == nil {
		t.Fatal("trusted assignment crossed a tenant")
	}
}
