package promptguard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

type Scanner struct {
	limits Limits
}

func New() *Scanner {
	return &Scanner{limits: DefaultLimits()}
}

func NewWithLimits(limits Limits) (*Scanner, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	return &Scanner{limits: limits}, nil
}

type candidate struct {
	path string
	kind SourceKind
}

var errDiscoveryLimit = errors.New("prompt guard discovery limit reached")

func (s *Scanner) Inspect(ctx context.Context, workspace string) (Report, error) {
	var report Report
	if s == nil {
		return report, errors.New("prompt guard scanner is nil")
	}
	if err := s.limits.validate(); err != nil {
		return report, err
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	absolute, err := filepath.Abs(workspace)
	if err != nil {
		return report, fmt.Errorf("resolve workspace for prompt guard: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return report, fmt.Errorf("inspect workspace for prompt guard: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return report, errors.New("prompt guard workspace must be a real directory")
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return report, fmt.Errorf("open workspace for prompt guard: %w", err)
	}
	defer root.Close()

	candidates, ignoredSymlinks, truncated, err := s.discover(ctx, root)
	report.IgnoredSymlinks = ignoredSymlinks
	report.DiscoveryTruncated = truncated
	if err != nil {
		return report, err
	}
	for index, item := range candidates {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if index >= s.limits.MaxFiles {
			report.SkippedByFileLimit += len(candidates) - index
			break
		}
		file, err := openSource(root, filepath.ToSlash(item.path))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return report, fmt.Errorf("open prompt guard source %s: %w", item.path, err)
		}
		fileInfo, statErr := file.Stat()
		if statErr != nil {
			_ = file.Close()
			return report, fmt.Errorf("inspect prompt guard source %s: %w", item.path, statErr)
		}
		if !fileInfo.Mode().IsRegular() {
			if err := file.Close(); err != nil {
				return report, fmt.Errorf("close prompt guard source %s: %w", item.path, err)
			}
			report.IgnoredBinary++
			continue
		}
		if fileInfo.Size() > s.limits.MaxFileBytes {
			if err := file.Close(); err != nil {
				return report, fmt.Errorf("close prompt guard source %s: %w", item.path, err)
			}
			report.SkippedOversized++
			continue
		}
		if report.ScannedBytes+fileInfo.Size() > s.limits.MaxTotalBytes {
			if err := file.Close(); err != nil {
				return report, fmt.Errorf("close prompt guard source %s: %w", item.path, err)
			}
			report.SkippedByByteLimit++
			continue
		}
		data, state, readErr := readBoundedText(file, s.limits.MaxFileBytes)
		closeErr := file.Close()
		if readErr != nil {
			return report, fmt.Errorf("read prompt guard source %s: %w", item.path, readErr)
		}
		if closeErr != nil {
			return report, fmt.Errorf("close prompt guard source %s: %w", item.path, closeErr)
		}
		switch state {
		case fileOversized:
			report.SkippedOversized++
			continue
		case fileBinary:
			report.IgnoredBinary++
			continue
		}
		if report.ScannedBytes+int64(len(data)) > s.limits.MaxTotalBytes {
			report.SkippedByByteLimit++
			continue
		}
		report.ScannedFiles++
		report.ScannedBytes += int64(len(data))
		report.Sources = append(report.Sources, Source{
			Path: item.path, Kind: item.kind, Fingerprint: fingerprint(data),
		})
		finding, found, analysisTruncated := detectBounded(item.path, item.kind, data)
		if analysisTruncated {
			report.AnalysisTruncated++
		}
		if found {
			report.Findings = append(report.Findings, finding)
		}
	}
	sort.Slice(report.Findings, func(left, right int) bool {
		return report.Findings[left].SourcePath < report.Findings[right].SourcePath
	})
	sort.Slice(report.Sources, func(left, right int) bool {
		return report.Sources[left].Path < report.Sources[right].Path
	})
	return report, nil
}

// Nonblocking open plus identity/type checks closes the discovery/open race:
// a replacement FIFO cannot hang preflight, and a replacement symlink cannot
// redirect the read to a different source. OpenRoot confines all resolution.
func openSource(root *os.Root, path string) (*os.File, error) {
	return openInspected(root, path, false)
}

func openInspected(root *os.Root, path string, directory bool) (*os.File, error) {
	before, err := root.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || (directory && !before.IsDir()) || (!directory && !before.Mode().IsRegular()) {
		return nil, errors.New("prompt guard source changed type")
	}
	flags := os.O_RDONLY | syscall.O_NONBLOCK
	if directory {
		flags |= syscall.O_DIRECTORY
	}
	file, err := root.OpenFile(path, flags, 0)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, errors.New("prompt guard source changed during open")
	}
	return file, nil
}

func (s *Scanner) discover(ctx context.Context, root *os.Root) ([]candidate, int, bool, error) {
	result := make([]candidate, 0)
	entries := 0
	ignoredSymlinks := 0
	var walk func(string) error
	walk = func(dir string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		file, err := openInspected(root, dir, true)
		if err != nil {
			return fmt.Errorf("open prompt guard directory: %w", err)
		}
		remaining := s.limits.MaxEntries - entries
		children, readErr := file.ReadDir(remaining + 1)
		closeErr := file.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		// Do not select an arbitrary filesystem-order subset of an oversized
		// directory. Report truncation without allocating its complete listing.
		if len(children) > remaining {
			return errDiscoveryLimit
		}
		entries += len(children)
		sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
		for _, entry := range children {
			if err := ctx.Err(); err != nil {
				return err
			}
			relative := filepath.Join(dir, entry.Name())
			if entry.Type()&os.ModeSymlink != 0 {
				ignoredSymlinks++
				continue
			}
			if unsafeRelativePath(relative) {
				continue
			}
			if entry.IsDir() {
				if !excludedDirectory(entry.Name()) {
					if err := walk(relative); err != nil {
						return err
					}
				}
				continue
			}
			if !entry.Type().IsRegular() {
				continue
			}
			if kind, relevant := classifySource(filepath.ToSlash(relative)); relevant {
				result = append(result, candidate{path: relative, kind: kind})
			}
		}
		return nil
	}
	err := walk(".")
	truncated := errors.Is(err, errDiscoveryLimit)
	if err != nil && !truncated {
		return nil, ignoredSymlinks, false, err
	}
	sort.Slice(result, func(left, right int) bool {
		leftPriority := sourcePriority(result[left])
		rightPriority := sourcePriority(result[right])
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		return result[left].path < result[right].path
	})
	return result, ignoredSymlinks, truncated, nil
}

func sourcePriority(value candidate) int {
	if value.kind == AgentInstructions {
		return 0
	}
	if !strings.Contains(filepath.ToSlash(value.path), "/") {
		return 1
	}
	switch value.kind {
	case AutomationConfig:
		return 2
	case RepositoryDocs:
		return 3
	default:
		return 4
	}
}

func unsafeRelativePath(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func excludedDirectory(name string) bool {
	switch strings.ToLower(name) {
	case ".git", ".ghost", ".cache", "bin", "build", "coverage", "dist", "fixtures", "node_modules", "out", "target", "testdata", "vendor":
		return true
	default:
		return false
	}
}

func classifySource(relative string) (SourceKind, bool) {
	lower := strings.ToLower(relative)
	base := strings.ToLower(filepath.Base(relative))
	depth := strings.Count(relative, "/")
	ext := strings.ToLower(filepath.Ext(base))

	switch base {
	case "agents.md", "claude.md", "gemini.md", ".cursorrules", ".clinerules", ".windsurfrules", "copilot-instructions.md":
		return AgentInstructions, true
	}
	if strings.HasPrefix(lower, ".cursor/rules/") || strings.HasPrefix(lower, ".claude/") || strings.HasPrefix(lower, ".github/instructions/") {
		return AgentInstructions, isTextExtension(ext)
	}
	if strings.HasPrefix(lower, ".github/") {
		return AutomationConfig, isTextExtension(ext)
	}
	if strings.HasPrefix(lower, "docs/") {
		return RepositoryDocs, isDocumentationExtension(ext)
	}
	if strings.HasPrefix(lower, "scripts/") {
		return InstructionScript, isScriptExtension(ext)
	}
	if depth == 0 && (strings.HasPrefix(base, "readme") || strings.HasPrefix(base, "contributing") || strings.HasPrefix(base, "security") ||
		strings.Contains(base, "instruction") || strings.Contains(base, "prompt")) {
		return RepositoryDocs, isTextExtension(ext)
	}
	return "", false
}

func isTextExtension(ext string) bool {
	return isDocumentationExtension(ext) || isScriptExtension(ext) || ext == ".json" || ext == ".toml"
}

func isDocumentationExtension(ext string) bool {
	switch ext {
	case ".md", ".mdc", ".txt", ".rst", ".adoc", ".yaml", ".yml":
		return true
	default:
		return false
	}
}

func isScriptExtension(ext string) bool {
	switch ext {
	case ".sh", ".bash", ".py", ".js", ".mjs", ".cjs", ".ts":
		return true
	default:
		return false
	}
}

type fileState uint8

const (
	fileText fileState = iota
	fileBinary
	fileOversized
)

func readBoundedText(file *os.File, maxBytes int64) ([]byte, fileState, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, fileText, err
	}
	if !info.Mode().IsRegular() {
		return nil, fileBinary, nil
	}
	if info.Size() > maxBytes {
		return nil, fileOversized, nil
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fileText, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fileOversized, nil
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return nil, fileBinary, nil
	}
	return data, fileText, nil
}

func fingerprint(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
