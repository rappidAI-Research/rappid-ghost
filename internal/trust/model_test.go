package trust

import "testing"

func TestClassesAreClosedAndDistinct(t *testing.T) {
	seen := make(map[Class]bool)
	for _, class := range []Class{Trusted, Untrusted, Sensitive, Shadow} {
		if !class.Valid() || seen[class] {
			t.Fatalf("invalid or duplicate trust class %q", class)
		}
		seen[class] = true
	}
	if Class("").Valid() || Class("UNKNOWN").Valid() {
		t.Fatal("unknown trust class accepted")
	}
}

func TestContextTransitionsAreMonotonic(t *testing.T) {
	var context Context
	context = context.ObserveUntrustedInput()
	var err error
	context, err = context.ObservePromptFinding(High)
	if err != nil {
		t.Fatal(err)
	}
	context, err = context.ObservePromptFinding(Low)
	if err != nil {
		t.Fatal(err)
	}
	context = context.ObserveShadowAccess()
	if err := context.Validate(); err != nil {
		t.Fatal(err)
	}
	if !context.UntrustedInputObserved || context.PromptSeverity != High || !context.ShadowResourceAccessed {
		t.Fatalf("context regressed: %+v", context)
	}
}

func TestContextRejectsContradictoryOrUnknownSeverity(t *testing.T) {
	if err := (Context{PromptSeverity: High}).Validate(); err == nil {
		t.Fatal("prompt severity without untrusted observation accepted")
	}
	if _, err := (Context{}).ObservePromptFinding("UNKNOWN"); err == nil {
		t.Fatal("unknown prompt severity accepted")
	}
}
