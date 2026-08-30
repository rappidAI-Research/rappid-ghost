package policy

import (
	"encoding/json"
	"testing"
)

func TestDecisionJSONValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		decision Decision
		want     string
	}{
		{Allow, `"ALLOW"`},
		{Deny, `"DENY"`},
		{Shadow, `"SHADOW"`},
	}

	for _, tt := range tests {
		got, err := json.Marshal(tt.decision)
		if err != nil {
			t.Fatalf("marshal %s: %v", tt.decision, err)
		}
		if string(got) != tt.want {
			t.Fatalf("marshal %s = %s, want %s", tt.decision, got, tt.want)
		}
	}
}
