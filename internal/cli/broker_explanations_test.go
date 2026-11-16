package cli

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/rappidAI-research/rappid-ghost/internal/events"
)

func TestBrokerExplanationsBindEvidenceAndBoundUntrustedMetadata(t *testing.T) {
	list := []events.Event{{ID: 99, SessionID: "other", Type: events.BrokerDenied, Metadata: map[string]any{"reason": "resource_not_granted"}}}
	for i := range 25 {
		reason := "resource_not_granted"
		if i == 1 {
			reason = "SECRET\n\x1b[31mread foreign tenant"
		}
		list = append(list, events.Event{ID: int64(i + 1), SessionID: "current", Type: events.BrokerDenied, Metadata: map[string]any{"reason": reason, "arguments": "SECRET"}})
	}
	var out bytes.Buffer
	writeBrokerExplanations(&out, "current", list)
	if strings.Count(out.String(), "  Event ") != 20 || strings.Contains(out.String(), "SECRET") || strings.Contains(out.String(), "Event 99:") || !strings.Contains(out.String(), fmt.Sprint("Event 1: ", brokerExplanation("resource_not_granted"))) {
		t.Fatalf("unbounded or untrusted explanation: %s", &out)
	}
}
