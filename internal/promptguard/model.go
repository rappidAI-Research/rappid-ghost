// Package promptguard performs bounded, deterministic inspection of selected
// workspace text before an isolated command starts. Findings are security
// signals; this package is not part of Ghost's isolation boundary.
package promptguard

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
)

type Severity string

const (
	Low      Severity = "LOW"
	Medium   Severity = "MEDIUM"
	High     Severity = "HIGH"
	Critical Severity = "CRITICAL"
)

func (s Severity) Valid() bool {
	switch s {
	case Low, Medium, High, Critical:
		return true
	default:
		return false
	}
}

func (s Severity) Rank() int {
	switch s {
	case Low:
		return 1
	case Medium:
		return 2
	case High:
		return 3
	case Critical:
		return 4
	default:
		return 0
	}
}

type Category string

const (
	InstructionOverride    Category = "INSTRUCTION_OVERRIDE"
	SecurityBypass         Category = "SECURITY_BYPASS"
	CredentialAccess       Category = "CREDENTIAL_ACCESS"
	NetworkTransmission    Category = "NETWORK_TRANSMISSION"
	EnvironmentExposure    Category = "ENVIRONMENT_EXPOSURE"
	SecuritySettingChange  Category = "SECURITY_SETTING_CHANGE"
	AuthorityImpersonation Category = "AUTHORITY_IMPERSONATION"
	Concealment            Category = "CONCEALMENT"
	Obfuscation            Category = "OBFUSCATION"
	EncodedInstructions    Category = "ENCODED_INSTRUCTIONS"
)

func (c Category) Valid() bool {
	switch c {
	case InstructionOverride, SecurityBypass, CredentialAccess, NetworkTransmission, EnvironmentExposure,
		SecuritySettingChange, AuthorityImpersonation, Concealment, Obfuscation, EncodedInstructions:
		return true
	default:
		return false
	}
}

type SourceKind string

const (
	AgentInstructions SourceKind = "AGENT_INSTRUCTIONS"
	RepositoryDocs    SourceKind = "REPOSITORY_DOCUMENTATION"
	AutomationConfig  SourceKind = "AUTOMATION_CONFIGURATION"
	InstructionScript SourceKind = "INSTRUCTION_SCRIPT"
)

func (s SourceKind) Valid() bool {
	switch s {
	case AgentInstructions, RepositoryDocs, AutomationConfig, InstructionScript:
		return true
	default:
		return false
	}
}

// Finding contains only location, rule identity, severity, and a one-way
// fingerprint. It intentionally contains no source excerpt or document body.
type Finding struct {
	SourcePath  string
	SourceKind  SourceKind
	Severity    Severity
	Categories  []Category
	RuleIDs     []string
	Line        int
	Fingerprint string
}

// Source identifies a selected text resource without retaining its contents.
// Every source was opened through the workspace root and analyzed within the
// scanner's deterministic bounds.
type Source struct {
	Path        string
	Kind        SourceKind
	Fingerprint string
}

type Report struct {
	ScannedFiles       int
	ScannedBytes       int64
	IgnoredBinary      int
	IgnoredSymlinks    int
	SkippedOversized   int
	SkippedByFileLimit int
	SkippedByByteLimit int
	AnalysisTruncated  int
	DiscoveryTruncated bool
	Sources            []Source
	Findings           []Finding
}

func (r Report) SuspiciousSources() int {
	return len(r.Findings)
}

func (r Report) Limited() bool {
	return r.SkippedOversized > 0 || r.SkippedByFileLimit > 0 || r.SkippedByByteLimit > 0 || r.AnalysisTruncated > 0 || r.DiscoveryTruncated
}

// Validate protects the orchestration boundary from an incomplete or
// contradictory inspector result. The production scanner always returns this
// shape; a broken inspector must not silently erase trust context.
func (r Report) Validate() error {
	if r.ScannedFiles != len(r.Sources) || r.ScannedFiles < 0 || r.ScannedBytes < 0 {
		return fmt.Errorf("prompt guard report has inconsistent scan counts")
	}
	sources := make(map[string]Source, len(r.Sources))
	for _, source := range r.Sources {
		if source.Path == "" || !source.Kind.Valid() || !validFingerprint(source.Fingerprint) {
			return fmt.Errorf("prompt guard report has invalid source metadata")
		}
		if _, exists := sources[source.Path]; exists {
			return fmt.Errorf("prompt guard report contains duplicate source %q", source.Path)
		}
		sources[source.Path] = source
	}
	for _, finding := range r.Findings {
		source, ok := sources[finding.SourcePath]
		if !ok || source.Kind != finding.SourceKind || source.Fingerprint != finding.Fingerprint ||
			!finding.Severity.Valid() || finding.Line < 1 || len(finding.Categories) == 0 || len(finding.RuleIDs) == 0 {
			return fmt.Errorf("prompt guard report has invalid finding metadata")
		}
		for _, category := range finding.Categories {
			if !category.Valid() {
				return fmt.Errorf("prompt guard report has invalid finding category %q", category)
			}
		}
		for _, ruleID := range finding.RuleIDs {
			if !validIdentifier(ruleID) {
				return fmt.Errorf("prompt guard report has invalid rule identifier")
			}
		}
	}
	return nil
}

func validIdentifier(value string) bool {
	if strings.TrimSpace(value) == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func validFingerprint(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil
}

type Inspector interface {
	Inspect(context.Context, string) (Report, error)
}

type Limits struct {
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxFiles      int
	MaxEntries    int
}

func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:  256 << 10,
		MaxTotalBytes: 4 << 20,
		MaxFiles:      256,
		MaxEntries:    20_000,
	}
}

func (l Limits) validate() error {
	if l.MaxFileBytes < 1 || l.MaxTotalBytes < l.MaxFileBytes || l.MaxFiles < 1 || l.MaxEntries < l.MaxFiles {
		return fmt.Errorf("invalid prompt guard scan limits")
	}
	return nil
}
