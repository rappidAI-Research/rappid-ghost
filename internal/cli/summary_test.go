package cli

import (
	"bytes"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
	"strings"
	"testing"
)

func TestBrokerDenialIsVisibleInSecuritySummary(t *testing.T) {
	var output bytes.Buffer
	value := session.Session{ID: "broker-summary", Runtime: "docker"}
	writeRunSummary(&output, value, []events.Event{{SessionID: value.ID, Type: events.BrokerDenied}})
	if !strings.Contains(output.String(), "Model/tool requests blocked") || strings.Contains(output.String(), "No security actions required.") {
		t.Fatal("broker denial was hidden")
	}
}
