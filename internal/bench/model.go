// Package bench runs reproducible, evidence-backed checks against Ghost's
// production runtime. A benchmark result describes only the property that was
// actually observed; it is not a general security score.
package bench

const SchemaVersion = 1

type Status string

const (
	Pass Status = "PASS"
	Fail Status = "FAIL"
	Skip Status = "SKIP"
)

type Options struct {
	Scenario   string
	RequireAll bool
}

type Report struct {
	Version int      `json:"version"`
	Results []Result `json:"results"`
	Summary Summary  `json:"summary"`
}

type Summary struct {
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
}

type Result struct {
	Scenario string           `json:"scenario"`
	Name     string           `json:"name"`
	Property string           `json:"property"`
	Status   Status           `json:"status"`
	Detail   string           `json:"detail"`
	Evidence []EvidenceBundle `json:"evidence"`
}

// EvidenceBundle refers only to evidence already produced by the Ghost
// session/event/provenance/incident pipeline. It intentionally contains no
// command output, decoy marker, credential-shaped value, headers, or bodies.
type EvidenceBundle struct {
	SessionID         string   `json:"session_id"`
	EventIDs          []int64  `json:"event_ids"`
	IncidentIDs       []string `json:"incident_ids"`
	ProvenanceNodeIDs []string `json:"provenance_node_ids"`
	ProvenanceEdgeIDs []string `json:"provenance_edge_ids"`
}

func newReport(results []Result) Report {
	report := Report{Version: SchemaVersion, Results: results}
	if report.Results == nil {
		report.Results = []Result{}
	}
	for index := range report.Results {
		if report.Results[index].Evidence == nil {
			report.Results[index].Evidence = []EvidenceBundle{}
		}
		switch report.Results[index].Status {
		case Pass:
			report.Summary.Passed++
		case Fail:
			report.Summary.Failed++
		case Skip:
			report.Summary.Skipped++
		}
	}
	return report
}

func (r Report) Successful() bool { return r.Summary.Failed == 0 }

// Complete is the release-gate result: every selected property was executed
// and passed. Ordinary benchmark use keeps SKIP distinct from FAIL, while
// release automation can reject an incomplete environment explicitly.
func (r Report) Complete() bool {
	return r.Summary.Failed == 0 && r.Summary.Skipped == 0
}
