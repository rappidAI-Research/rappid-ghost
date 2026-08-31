package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/deception"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
}

func Open(ctx context.Context, path string) (*Store, error) {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("SQLite database directory must be a real directory")
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return nil, fmt.Errorf("secure database directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if closeErr := file.Close(); closeErr != nil {
			return nil, fmt.Errorf("create SQLite database: %w", closeErr)
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create SQLite database: %w", err)
	}
	if info, statErr := os.Lstat(path); statErr == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, errors.New("refusing to open a non-regular or symlinked SQLite database")
	} else if statErr != nil {
		return nil, fmt.Errorf("inspect SQLite database path: %w", statErr)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("secure SQLite database: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	// PRAGMAs are connection-local. A single connection keeps their security
	// and durability behavior consistent for this local CLI process.
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("configure SQLite: %w", err)
		}
	}
	store := &Store{db: db}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin database migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at_ns INTEGER NOT NULL
)`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}

	rows, err := tx.QueryContext(ctx, "SELECT version FROM schema_migrations ORDER BY version ASC")
	if err != nil {
		return fmt.Errorf("read schema versions: %w", err)
	}
	version := 0
	for rows.Next() {
		var applied int
		if err := rows.Scan(&applied); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read schema version: %w", err)
		}
		if applied != version+1 {
			_ = rows.Close()
			return fmt.Errorf("database migration history is not contiguous: expected version %d, found %d", version+1, applied)
		}
		version = applied
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate schema versions: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close schema version query: %w", err)
	}
	if version > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this Ghost build", version)
	}
	for index := version; index < len(migrations); index++ {
		if _, err := tx.ExecContext(ctx, migrations[index]); err != nil {
			return fmt.Errorf("apply database migration %d: %w", index+1, err)
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO schema_migrations(version, applied_at_ns) VALUES (?, ?)",
			index+1, time.Now().UTC().UnixNano()); err != nil {
			return fmt.Errorf("record database migration %d: %w", index+1, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit database migration: %w", err)
	}
	return nil
}

var migrations = []string{`
CREATE TABLE sessions (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    created_at_ns INTEGER NOT NULL,
    completed_at_ns INTEGER,
    command_json TEXT NOT NULL,
    runtime TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('created', 'running', 'completed', 'failed')),
    exit_code INTEGER
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    timestamp_ns INTEGER NOT NULL,
    type TEXT NOT NULL,
    subject TEXT,
    resource TEXT,
    action TEXT,
    decision TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX events_session_order_idx ON events(session_id, timestamp_ns, id);
CREATE INDEX sessions_latest_idx ON sessions(created_at_ns DESC, seq DESC);
`, `
CREATE TABLE decoys (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    guest_path TEXT NOT NULL,
    marker TEXT NOT NULL UNIQUE,
    created_at_ns INTEGER NOT NULL,
    triggered INTEGER NOT NULL DEFAULT 0 CHECK (triggered IN (0, 1)),
    triggered_at_ns INTEGER,
    UNIQUE(session_id, guest_path)
);

CREATE INDEX decoys_session_order_idx ON decoys(session_id, created_at_ns, id);
`, `
ALTER TABLE sessions ADD COLUMN network_mode TEXT NOT NULL DEFAULT 'deny';
ALTER TABLE sessions ADD COLUMN contained INTEGER NOT NULL DEFAULT 0 CHECK (contained IN (0, 1));
`}

func (s *Store) CreateSession(ctx context.Context, value session.Session) error {
	if value.ID == "" || len(value.Command) == 0 || !value.Status.Valid() {
		return errors.New("invalid session")
	}
	commandJSON, err := json.Marshal(value.Command)
	if err != nil {
		return fmt.Errorf("encode session command: %w", err)
	}
	networkMode := value.NetworkMode
	if networkMode == "" {
		networkMode = ghostnetwork.Deny
	}
	if networkMode != ghostnetwork.Deny && networkMode != ghostnetwork.Allowlist {
		return errors.New("invalid session network mode")
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO sessions(id, created_at_ns, completed_at_ns, command_json, runtime, status, exit_code, network_mode, contained)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, value.ID, value.CreatedAt.UTC().UnixNano(), timeToNull(value.CompletedAt),
		string(commandJSON), value.Runtime, value.Status, intToNull(value.ExitCode), networkMode, boolToInt(value.Contained))
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (s *Store) UpdateSession(ctx context.Context, value session.Session) error {
	if value.ID == "" || !value.Status.Valid() {
		return errors.New("invalid session")
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE sessions SET completed_at_ns = ?, status = ?, exit_code = ?, contained = ? WHERE id = ?`,
		timeToNull(value.CompletedAt), value.Status, intToNull(value.ExitCode), boolToInt(value.Contained), value.ID)
	if err != nil {
		return fmt.Errorf("update session: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read updated session count: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("update session: %w", ErrNotFound)
	}
	return nil
}

func (s *Store) AddEvent(ctx context.Context, event *events.Event) error {
	if event == nil || event.SessionID == "" || event.Type == "" {
		return errors.New("invalid event")
	}
	metadata := event.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("encode event metadata: %w", err)
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO events(session_id, timestamp_ns, type, subject, resource, action, decision, metadata_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, event.SessionID, event.Timestamp.UTC().UnixNano(), event.Type,
		nullString(event.Subject), nullString(event.Resource), nullString(event.Action), decisionToNull(event.Decision), string(metadataJSON))
	if err != nil {
		return fmt.Errorf("add event: %w", err)
	}
	event.ID, err = result.LastInsertId()
	if err != nil {
		return fmt.Errorf("read event ID: %w", err)
	}
	return nil
}

func (s *Store) CreateDecoy(ctx context.Context, decoy deception.Decoy) error {
	if decoy.ID == "" || decoy.SessionID == "" || decoy.Type == "" || decoy.GuestPath == "" || decoy.Marker == "" || decoy.CreatedAt.IsZero() {
		return errors.New("invalid decoy")
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO decoys(id, session_id, type, guest_path, marker, created_at_ns, triggered, triggered_at_ns)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, decoy.ID, decoy.SessionID, decoy.Type, decoy.GuestPath,
		decoy.Marker, decoy.CreatedAt.UTC().UnixNano(), boolToInt(decoy.Triggered), timeToNull(decoy.TriggeredAt))
	if err != nil {
		return fmt.Errorf("create decoy: %w", err)
	}
	return nil
}

// TriggerDecoy atomically records the first access. The boolean is false when
// the decoy was already triggered, allowing callers to avoid duplicate events.
func (s *Store) TriggerDecoy(ctx context.Context, sessionID, id string, triggeredAt time.Time) (bool, error) {
	if sessionID == "" || id == "" || triggeredAt.IsZero() {
		return false, errors.New("invalid decoy trigger")
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE decoys SET triggered = 1, triggered_at_ns = ? WHERE session_id = ? AND id = ? AND triggered = 0`,
		triggeredAt.UTC().UnixNano(), sessionID, id)
	if err != nil {
		return false, fmt.Errorf("trigger decoy: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read triggered decoy count: %w", err)
	}
	if rows > 0 {
		return true, nil
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, "SELECT 1 FROM decoys WHERE session_id = ? AND id = ?", sessionID, id).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("trigger decoy: %w", ErrNotFound)
	} else if err != nil {
		return false, fmt.Errorf("find decoy: %w", err)
	}
	return false, nil
}

func (s *Store) Decoys(ctx context.Context, sessionID string) ([]deception.Decoy, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, session_id, type, guest_path, marker, created_at_ns, triggered, triggered_at_ns
FROM decoys WHERE session_id = ? ORDER BY created_at_ns ASC, id ASC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("query decoys: %w", err)
	}
	defer rows.Close()

	var result []deception.Decoy
	for rows.Next() {
		var decoy deception.Decoy
		var createdNS int64
		var triggered int
		var triggeredNS sql.NullInt64
		if err := rows.Scan(&decoy.ID, &decoy.SessionID, &decoy.Type, &decoy.GuestPath, &decoy.Marker,
			&createdNS, &triggered, &triggeredNS); err != nil {
			return nil, fmt.Errorf("read decoy: %w", err)
		}
		decoy.CreatedAt = time.Unix(0, createdNS).UTC()
		decoy.Triggered = triggered == 1
		if triggeredNS.Valid {
			value := time.Unix(0, triggeredNS.Int64).UTC()
			decoy.TriggeredAt = &value
		}
		result = append(result, decoy)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate decoys: %w", err)
	}
	return result, nil
}

func (s *Store) Session(ctx context.Context, id string) (session.Session, error) {
	return scanSession(s.db.QueryRowContext(ctx, `
SELECT id, created_at_ns, completed_at_ns, command_json, runtime, status, exit_code, network_mode, contained
FROM sessions WHERE id = ?`, id))
}

func (s *Store) LatestSession(ctx context.Context) (session.Session, error) {
	return scanSession(s.db.QueryRowContext(ctx, `
SELECT id, created_at_ns, completed_at_ns, command_json, runtime, status, exit_code, network_mode, contained
FROM sessions ORDER BY created_at_ns DESC, seq DESC LIMIT 1`))
}

func scanSession(row *sql.Row) (session.Session, error) {
	var value session.Session
	var createdNS int64
	var completedNS sql.NullInt64
	var commandJSON string
	var exitCode sql.NullInt64
	var contained int
	if err := row.Scan(&value.ID, &createdNS, &completedNS, &commandJSON, &value.Runtime, &value.Status, &exitCode, &value.NetworkMode, &contained); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return session.Session{}, ErrNotFound
		}
		return session.Session{}, fmt.Errorf("read session: %w", err)
	}
	value.Contained = contained == 1
	value.CreatedAt = time.Unix(0, createdNS).UTC()
	if completedNS.Valid {
		completed := time.Unix(0, completedNS.Int64).UTC()
		value.CompletedAt = &completed
	}
	if exitCode.Valid {
		code := int(exitCode.Int64)
		value.ExitCode = &code
	}
	if err := json.Unmarshal([]byte(commandJSON), &value.Command); err != nil {
		return session.Session{}, fmt.Errorf("decode session command: %w", err)
	}
	return value, nil
}

func (s *Store) Events(ctx context.Context, sessionID string) ([]events.Event, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, session_id, timestamp_ns, type, subject, resource, action, decision, metadata_json
FROM events WHERE session_id = ? ORDER BY timestamp_ns ASC, id ASC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var result []events.Event
	for rows.Next() {
		var event events.Event
		var timestampNS int64
		var subject, resource, action, decision sql.NullString
		var metadataJSON string
		if err := rows.Scan(&event.ID, &event.SessionID, &timestampNS, &event.Type, &subject, &resource, &action, &decision, &metadataJSON); err != nil {
			return nil, fmt.Errorf("read event: %w", err)
		}
		event.Timestamp = time.Unix(0, timestampNS).UTC()
		event.Subject = subject.String
		event.Resource = resource.String
		event.Action = action.String
		if decision.Valid {
			value := policy.Decision(decision.String)
			event.Decision = &value
		}
		if err := json.Unmarshal([]byte(metadataJSON), &event.Metadata); err != nil {
			return nil, fmt.Errorf("decode event metadata: %w", err)
		}
		result = append(result, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate events: %w", err)
	}
	return result, nil
}

func timeToNull(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().UnixNano()
}

func intToNull(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func decisionToNull(value *policy.Decision) any {
	if value == nil {
		return nil
	}
	return *value
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
