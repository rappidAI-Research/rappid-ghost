// Package promptguard performs bounded, deterministic inspection of selected
// workspace text before an isolated command starts. Findings are security
// signals; this package is not part of Ghost's isolation boundary.
package promptguard

import (
	"context"
	"fmt"
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

type SourceKind string

const (
	AgentInstructions SourceKind = "AGENT_INSTRUCTIONS"
	RepositoryDocs    SourceKind = "REPOSITORY_DOCUMENTATION"
	AutomationConfig  SourceKind = "AUTOMATION_CONFIGURATION"
	InstructionScript SourceKind = "INSTRUCTION_SCRIPT"
)

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
	Findings           []Finding
}

func (r Report) SuspiciousSources() int {
	return len(r.Findings)
}

func (r Report) Limited() bool {
	return r.SkippedOversized > 0 || r.SkippedByFileLimit > 0 || r.SkippedByByteLimit > 0 || r.AnalysisTruncated > 0 || r.DiscoveryTruncated
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
