package broker

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/rappidAI-research/rappid-ghost/internal/safefile"
)

func newID() string              { return rand.Text() }
func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }
func SocketDirectory(sessionID string) (string, error) {
	if len(sessionID) < 1 || len(sessionID) > 128 || strings.ContainsAny(sessionID, "/\\\x00\r\n") {
		return "", errors.New("invalid broker session identity")
	}
	sum := sha256.Sum256([]byte(sessionID))
	// Fixed Linux temp root avoids recovery ambiguity if TMPDIR changes.
	return fmt.Sprintf("/tmp/ghost-broker-%d-%x", os.Getuid(), sum[:16]), nil
}
func createDirectory(sessionID string) (string, error) {
	dir, err := SocketDirectory(sessionID)
	if err != nil {
		return "", err
	}
	if err = os.Mkdir(dir, 0700); err != nil {
		return "", errors.New("broker session directory already exists or is unavailable; reconcile the recorded session first")
	}
	owner := filepath.Join(dir, "owner")
	if err = os.WriteFile(owner, []byte(sessionID), 0600); err != nil {
		_ = os.Remove(dir)
		return "", err
	}
	return dir, nil
}

// Cleanup removes only the exact session-derived private directory after
// validating ownership, type, marker and closed artifact names; never recurse.
func Cleanup(sessionID string) error {
	dir, err := SocketDirectory(sessionID)
	if err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return errors.New("ambiguous broker directory ownership")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return os.Remove(dir)
	}
	owner, err := safefile.ReadRegular(filepath.Join(dir, "owner"), 128)
	if err != nil || string(owner) != sessionID {
		return errors.New("ambiguous broker ownership marker")
	}
	for _, e := range entries {
		switch e.Name() {
		case "owner":
			if !e.Type().IsRegular() {
				return errors.New("ambiguous broker marker type")
			}
		case "helper":
			file, err := e.Info()
			if err != nil {
				return err
			}
			stat, ok := file.Sys().(*syscall.Stat_t)
			if !ok || int(stat.Uid) != os.Getuid() || !file.Mode().IsRegular() || file.Mode().Perm() != 0500 || file.Size() > 64*1024*1024 {
				return errors.New("ambiguous broker helper artifact")
			}
		case "broker.sock":
			if e.Type()&os.ModeSocket == 0 {
				return errors.New("ambiguous broker socket type")
			}
		default:
			return errors.New("unknown broker artifact; refusing cleanup")
		}
	}
	for _, e := range entries {
		if err = os.Remove(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return os.Remove(dir)
}

// ValidateWorkspace excludes the private IPC root and its session trees even
// from legacy/unbrokered runs, so a broadly mounted /tmp cannot expose another
// session's socket capability. The caller supplies a canonical workspace.
var privateDirectoryName = regexp.MustCompile(`^ghost-broker-[0-9]+-[a-f0-9]{32}$`)

func ValidateWorkspace(workspace string) error {
	root, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(workspace, root)
	if err != nil {
		return err
	}
	if rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("workspace contains Ghost's private IPC root; select a dedicated project directory instead")
	}
	rel, err = filepath.Rel(root, workspace)
	if err != nil {
		return err
	}
	first := strings.Split(rel, string(os.PathSeparator))[0]
	if privateDirectoryName.MatchString(first) {
		return errors.New("Ghost private broker directories cannot be exposed as a workspace")
	}
	return nil
}
