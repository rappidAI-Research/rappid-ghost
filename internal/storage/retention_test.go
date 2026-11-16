package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/events"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
)

func retentionFixture(t *testing.T) (*Store, string) {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "sessions")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), filepath.Join(root, "ghost.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, directory
}

func retainedSession(t *testing.T, s *Store, directory string, status session.Status, completed time.Time, pending bool) session.Session {
	t.Helper()
	id, err := session.NewID()
	if err != nil {
		t.Fatal(err)
	}
	v := session.Session{ID: id, CreatedAt: completed.Add(-time.Hour), Command: []string{"synthetic-agent"}, Runtime: "docker", Status: status, SecurityState: policy.StateNormal, CleanupPending: pending}
	if status == session.Completed || status == session.Failed {
		v.CompletedAt = &completed
	}
	if err = s.CreateSession(context.Background(), v); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(directory, id), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, id, "retained.log"), []byte("synthetic operation"), 0600); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPruneDeletesOnlyCompletedCleanHistoryAndItsOwnedArtifacts(t *testing.T) {
	s, directory := retentionFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-40 * 24 * time.Hour)
	eligible := []session.Session{retainedSession(t, s, directory, session.Completed, old, false), retainedSession(t, s, directory, session.Failed, old, false)}
	kept := []session.Session{retainedSession(t, s, directory, session.Running, old, false), retainedSession(t, s, directory, session.Created, old, false), retainedSession(t, s, directory, session.Completed, old, true), retainedSession(t, s, directory, session.Completed, now.Add(-time.Hour), false)}
	event := &events.Event{SessionID: eligible[0].ID, Timestamp: old, Type: events.ProcessStart, Metadata: map[string]any{"synthetic": "SYNTHETIC_RETENTION_PAYLOAD"}}
	if err := s.AddEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	protected := filepath.Join(outside, "keep.txt")
	if err := os.WriteFile(protected, []byte("keep outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, eligible[0].ID, "external-link")); err != nil {
		t.Fatal(err)
	}
	cutoff := now.Add(-30 * 24 * time.Hour)
	preview, err := s.Prune(ctx, directory, cutoff, true)
	if err != nil || preview.Eligible != 2 || preview.Removed != 0 || preview.Pending {
		t.Fatalf("preview %+v %v", preview, err)
	}
	for _, v := range eligible {
		if _, err := s.Session(ctx, v.ID); err != nil {
			t.Fatal("dry-run deleted history")
		}
	}
	report, err := s.Prune(ctx, directory, cutoff, false)
	if err != nil || report.Removed != 2 {
		t.Fatalf("prune %+v %v", report, err)
	}
	for _, v := range eligible {
		if _, err := s.Session(ctx, v.ID); !errors.Is(err, ErrNotFound) {
			t.Fatal("retired row remains")
		}
		if _, err := os.Lstat(filepath.Join(directory, v.ID)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("retired artifact remains")
		}
	}
	for _, v := range kept {
		if _, err := s.Session(ctx, v.ID); err != nil {
			t.Fatal("prune changed active/unclean/recent history")
		}
		if _, err := os.Stat(filepath.Join(directory, v.ID, "retained.log")); err != nil {
			t.Fatal("prune changed protected session artifact")
		}
	}
	if data, err := os.ReadFile(protected); err != nil || string(data) != "keep outside" {
		t.Fatal("retention followed a nested external symlink")
	}
	for _, suffix := range []string{"", "-wal"} {
		data, err := os.ReadFile(s.path + suffix)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "SYNTHETIC_RETENTION_PAYLOAD") {
			t.Fatal("completed SQLite pruning retained deleted payload")
		}
	}
	var count int
	if err = s.db.QueryRowContext(ctx, "SELECT last_removed_count FROM evidence_maintenance WHERE id=1").Scan(&count); err != nil || count != 2 {
		t.Fatal("bounded retention receipt missing")
	}
}

func TestPruneHonorsLiveProjectLockAndRefusesAmbiguousPaths(t *testing.T) {
	s, directory := retentionFixture(t)
	ctx := context.Background()
	cutoff := time.Now().Add(-24 * time.Hour)
	v := retainedSession(t, s, directory, session.Completed, cutoff.Add(-24*time.Hour), false)
	lock, err := session.AcquireProjectLock(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Prune(ctx, directory, cutoff, false); !errors.Is(err, session.ErrProjectBusy) {
		t.Fatal("retention bypassed active execution lock")
	}
	_ = lock.Close()
	if err = os.RemoveAll(filepath.Join(directory, v.ID)); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err = os.WriteFile(filepath.Join(outside, "protected"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, filepath.Join(directory, v.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Prune(ctx, directory, cutoff, false); err == nil {
		t.Fatal("ambiguous top-level artifact accepted")
	}
	if _, err = os.Stat(filepath.Join(outside, "protected")); err != nil {
		t.Fatal("external target modified")
	}
	if _, err = s.Prune(ctx, t.TempDir(), cutoff, false); err == nil {
		t.Fatal("foreign project root accepted")
	}
}

type retentionRuntime struct{ calls int }

func (r *retentionRuntime) Name() string { return "docker" }
func (r *retentionRuntime) Run(context.Context, ghruntime.RunRequest) (ghruntime.RunResult, error) {
	r.calls++
	return ghruntime.RunResult{Started: true, SecurityState: policy.StateNormal}, nil
}

func TestInterruptedRetentionResumesBeforeAnotherAgentStarts(t *testing.T) {
	s, directory := retentionFixture(t)
	ctx := context.Background()
	cutoff := time.Now().Add(-24 * time.Hour)
	v := retainedSession(t, s, directory, session.Completed, cutoff.Add(-24*time.Hour), false)
	// Durable state at a real crash boundary: requested cutoff committed and
	// owned directory already removed, but the row deletion has not committed.
	if _, err := s.db.ExecContext(ctx, "UPDATE evidence_maintenance SET cutoff_ns=? WHERE id=1", cutoff.UnixNano()); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(directory, v.ID)); err != nil {
		t.Fatal(err)
	}
	runner := &retentionRuntime{}
	manager := session.NewManager(s, runner)
	value, err := manager.Run(ctx, session.RunRequest{Runtime: ghruntime.RunRequest{Command: []string{"true"}, Workspace: filepath.Dir(directory)}, SessionsDir: directory, HomePolicy: "deny"})
	if err != nil || value.Status != session.Completed || runner.calls != 1 {
		t.Fatalf("resume/run %+v %v calls=%d", value, err, runner.calls)
	}
	if _, err = s.Session(ctx, v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("old intent did not resume")
	}
	if _, err = s.Session(ctx, value.ID); err != nil {
		t.Fatal("maintenance affected the newly started session")
	}
}

func TestRetentionRejectsSessionTraversalAndNestedMounts(t *testing.T) {
	s, directory := retentionFixture(t)
	ctx := context.Background()
	old := time.Now().Add(-48 * time.Hour)
	v := session.Session{ID: "../outside", CreatedAt: old, CompletedAt: &old, Command: []string{"true"}, Runtime: "docker", Status: session.Completed, SecurityState: policy.StateNormal}
	if err := s.CreateSession(ctx, v); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prune(ctx, directory, time.Now().Add(-24*time.Hour), false); err == nil {
		t.Fatal("unsafe stored identity accepted")
	}
	for _, mount := range []string{"/tmp/retention/session", "/tmp/retention/session/nested", "/tmp/with\\040space/session"} {
		target := "/tmp/retention/session"
		if strings.Contains(mount, "\\040") {
			target = "/tmp/with space/session"
		}
		line := []byte("36 25 0:32 / " + mount + " rw - tmpfs tmpfs rw\n")
		if checkSessionMounts(line, target) == nil {
			t.Fatal("nested mount accepted")
		}
	}
	if err := checkSessionMounts([]byte("36 25 0:32 / /tmp/retention/session-other rw - tmpfs tmpfs rw\n"), "/tmp/retention/session"); err != nil {
		t.Fatal("sibling mount rejected")
	}
}
