package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/session"
)

type PruneReport struct {
	SchemaVersion int        `json:"schema_version"`
	Cutoff        time.Time  `json:"requested_cutoff"`
	DryRun        bool       `json:"dry_run"`
	PendingCutoff *time.Time `json:"previously_requested_cutoff,omitempty"`
	Eligible      int        `json:"eligible_sessions"`
	Removed       int        `json:"removed_sessions"`
	Pending       bool       `json:"previously_requested_maintenance"`
}

var pruneID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)

func (s *Store) pruneRoot(directory string) (*os.Root, error) {
	abs, err := filepath.Abs(directory)
	if err != nil || abs != filepath.Join(filepath.Dir(s.path), "sessions") {
		return nil, errors.New("retention requires this database's own sessions directory")
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("retention sessions root must be a real private directory")
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	bound, err := root.Stat(".")
	if err != nil || !os.SameFile(info, bound) {
		_ = root.Close()
		return nil, errors.New("retention sessions root changed")
	}
	return root, nil
}

// Prune journals an explicit trusted cutoff, never chooses retention from a
// heuristic/profile. Caller cancellation leaves a resumable fixed predicate.
func (s *Store) Prune(ctx context.Context, directory string, cutoff time.Time, dryRun bool) (PruneReport, error) {
	report := PruneReport{SchemaVersion: 1, Cutoff: cutoff.UTC(), DryRun: dryRun}
	if cutoff.IsZero() || !cutoff.Before(time.Now()) {
		return report, errors.New("retention cutoff must be an explicit past time")
	}
	root, err := s.pruneRoot(directory)
	if err != nil {
		return report, err
	}
	defer root.Close()
	lock, err := session.AcquireProjectLock(directory)
	if err != nil {
		return report, err
	}
	defer lock.Close()
	var pending sql.NullInt64
	if err = s.db.QueryRowContext(ctx, "SELECT cutoff_ns FROM evidence_maintenance WHERE id=1").Scan(&pending); err != nil {
		return report, err
	}
	report.Pending = pending.Valid
	if pending.Valid {
		value := time.Unix(0, pending.Int64).UTC()
		report.PendingCutoff = &value
	}
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE status IN ('completed','failed') AND completed_at_ns < ? AND cleanup_pending=0`, cutoff.UTC().UnixNano()).Scan(&report.Eligible); err != nil {
		return report, err
	}
	if dryRun {
		return report, nil
	}
	if pending.Valid {
		report.Removed, err = s.resumePrune(ctx, directory, root)
		if err != nil {
			return report, err
		}
	}
	if _, err = s.db.ExecContext(ctx, "UPDATE evidence_maintenance SET cutoff_ns=?,removed_count=0 WHERE id=1 AND cutoff_ns IS NULL", cutoff.UTC().UnixNano()); err != nil {
		return report, err
	}
	n, err := s.resumePrune(ctx, directory, root)
	report.Removed += n
	return report, err
}

// ResumeMaintenance is called by the session manager under its existing project
// lock, after runtime recovery and before a new session. No new cutoff is chosen.
func (s *Store) ResumeMaintenance(ctx context.Context, directory string) error {
	var pending sql.NullInt64
	if err := s.db.QueryRowContext(ctx, "SELECT cutoff_ns FROM evidence_maintenance WHERE id=1").Scan(&pending); err != nil {
		return err
	}
	if !pending.Valid {
		return nil
	}
	root, err := s.pruneRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	_, err = s.resumePrune(ctx, directory, root)
	return err
}

func (s *Store) eligibleBatch(ctx context.Context, cutoff int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM sessions WHERE status IN ('completed','failed') AND completed_at_ns < ? AND cleanup_pending=0 ORDER BY completed_at_ns,id LIMIT 128`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if !pruneID.MatchString(id) {
			return nil, errors.New("retention refuses a noncanonical session identity")
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) resumePrune(ctx context.Context, directory string, root *os.Root) (int, error) {
	var cutoff sql.NullInt64
	if err := s.db.QueryRowContext(ctx, "SELECT cutoff_ns FROM evidence_maintenance WHERE id=1").Scan(&cutoff); err != nil {
		return 0, err
	}
	if !cutoff.Valid {
		return 0, nil
	}
	removed := 0
	for {
		ids, err := s.eligibleBatch(ctx, cutoff.Int64)
		if err != nil {
			return removed, err
		}
		if len(ids) == 0 {
			break
		}
		for _, id := range ids {
			if err = ctx.Err(); err != nil {
				return removed, err
			}
			info, statErr := root.Lstat(id)
			if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
				return removed, statErr
			}
			if statErr == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
				return removed, errors.New("retention refuses an ambiguous session artifact")
			}
			if err = refuseSessionMounts(directory, id); err != nil {
				return removed, err
			}
			if err = root.RemoveAll(id); err != nil {
				return removed, fmt.Errorf("remove retained session directory: %w", err)
			}
			// A crash between filesystem removal and this transaction is safe:
			// the fixed predicate and row remain, so a missing directory is retried.
			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				return removed, err
			}
			result, deleteErr := tx.ExecContext(ctx, `DELETE FROM sessions WHERE id=? AND status IN ('completed','failed') AND completed_at_ns < ? AND cleanup_pending=0 AND EXISTS(SELECT 1 FROM evidence_maintenance WHERE id=1 AND cutoff_ns=?)`, id, cutoff.Int64, cutoff.Int64)
			var rows int64
			if deleteErr == nil {
				rows, deleteErr = result.RowsAffected()
			}
			if deleteErr == nil && rows != 1 {
				deleteErr = errors.New("retention session ownership changed")
			}
			if deleteErr == nil {
				_, deleteErr = tx.ExecContext(ctx, "UPDATE evidence_maintenance SET removed_count=removed_count+1 WHERE id=1")
			}
			if deleteErr != nil {
				_ = tx.Rollback()
				return removed, deleteErr
			}
			if err = tx.Commit(); err != nil {
				return removed, err
			}
			removed++
		}
	}
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT removed_count FROM evidence_maintenance WHERE id=1").Scan(&count); err != nil {
		return removed, err
	}
	if count > 0 {
		// Reclaim SQLite pages and old WAL frames. Busy readers and low disk space
		// are visible failures; the durable cutoff remains pending until success.
		if _, err := s.db.ExecContext(ctx, "VACUUM"); err != nil {
			return removed, fmt.Errorf("reclaim retained evidence: %w", err)
		}
		var busy, logFrames, checkpointed int
		if err := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointed); err != nil {
			return removed, err
		}
		if busy != 0 {
			return removed, errors.New("retention checkpoint is blocked by a SQLite reader; close database readers and retry ghost prune")
		}
	}
	_, err := s.db.ExecContext(ctx, `UPDATE evidence_maintenance SET last_completed_at_ns=?,last_cutoff_ns=cutoff_ns,last_removed_count=removed_count,cutoff_ns=NULL,removed_count=0 WHERE id=1`, time.Now().UTC().UnixNano())
	return removed, err
}
