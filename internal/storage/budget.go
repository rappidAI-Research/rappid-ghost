package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// Zero is used by inspection/explicit maintenance, never by configured runs.
// This limits SQLite pages and WAL write admission, not the entire filesystem.
type Options struct{ MaxDatabaseMiB int }

const maxEvidenceRecordBytes = 64 * 1024
const finalizationReserveBytes = 1024 * 1024

var ErrCapacity = errors.New("Ghost evidence database budget exhausted; inspect history and explicitly prune completed sessions")
var ErrRecordLimit = errors.New("Ghost evidence record exceeds the bounded storage contract")

func (s *Store) configureBudget(ctx context.Context) error {
	if s.maxBytes == 0 {
		return nil
	}
	var pageSize, pages int64
	if err := s.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return err
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		return err
	}
	if pageSize < 512 || pages*pageSize > s.maxBytes {
		return ErrCapacity
	}
	wanted := s.maxBytes / pageSize
	if err := s.db.Close(); err != nil {
		return err
	}
	limited, err := openDatabase(s.path, wanted)
	if err != nil {
		return err
	}
	s.db = limited
	var actual int64
	if err := s.db.QueryRowContext(ctx, "PRAGMA max_page_count").Scan(&actual); err != nil {
		return err
	}
	if actual != wanted {
		return ErrCapacity
	}
	return nil
}

// Keep finite headroom for terminal status/cleanup updates and SESSION_END.
// SQLite enforces the hard main-page ceiling even if multiple callers race.
// Normal evidence writers serialize the additional used-page/WAL checks.
func (s *Store) admitWrite(ctx context.Context) error {
	if s.maxBytes == 0 {
		return nil
	}
	var used int64
	if err := s.db.QueryRowContext(ctx, `SELECT (p.page_count-f.freelist_count)*s.page_size FROM pragma_page_count AS p, pragma_freelist_count AS f, pragma_page_size AS s`).Scan(&used); err != nil {
		return err
	}
	if used >= s.maxBytes-finalizationReserveBytes {
		return ErrCapacity
	}
	info, err := os.Lstat(s.path + "-wal")
	if err == nil {
		if !info.Mode().IsRegular() || info.Size() > s.maxBytes {
			return ErrCapacity
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect evidence WAL: %w", err)
	}
	return nil
}
