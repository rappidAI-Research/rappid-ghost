package policy

import (
	"encoding/json"
	"testing"
)

func TestHomeResourceDecision(t *testing.T) {
	tests := []struct {
		name             string
		home             string
		deceptionEnabled bool
		resourceEnabled  bool
		want             Decision
		wantErr          bool
	}{
		{name: "shadow enabled", home: HomeShadow, deceptionEnabled: true, resourceEnabled: true, want: Shadow},
		{name: "deception disabled fails closed", home: HomeShadow, deceptionEnabled: false, resourceEnabled: true, want: Deny},
		{name: "resource disabled fails closed", home: HomeShadow, deceptionEnabled: true, resourceEnabled: false, want: Deny},
		{name: "deny", home: HomeDeny, deceptionEnabled: true, resourceEnabled: true, want: Deny},
		{name: "invalid", home: "allow", deceptionEnabled: true, resourceEnabled: true, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HomeResourceDecision(tt.home, tt.deceptionEnabled, tt.resourceEnabled)
			if (err != nil) != tt.wantErr {
				t.Fatalf("HomeResourceDecision() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("HomeResourceDecision() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecisionsSerializeCanonically(t *testing.T) {
	value, err := json.Marshal([]Decision{Allow, Deny, Shadow})
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != `["ALLOW","DENY","SHADOW"]` {
		t.Fatalf("serialized decisions = %s", value)
	}
}
