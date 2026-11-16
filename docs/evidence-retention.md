# Evidence budget and explicit retention

Ghost keeps its existing local `.ghost/ghost.db` and per-session directories.
There is no second event store and no automatic age-based deletion. Application
payloads, model prompts/responses and broker credentials are excluded from normal
broker events. Agent stdout and files intentionally written to the workspace are
application data; operators must handle them separately.

## Budget

```yaml
evidence:
  max_database_mib: 128
```

Omission preserves compatibility with v0.5 configuration and selects 128 MiB.
Explicit values must be 8..4096 MiB. Normal runs impose SQLite's hard main-page
ceiling on **every connection**, bound individual new evidence records to 64 KiB,
and stop normal writes before the ceiling to reserve 1 MiB for terminal status
and cleanup evidence. Used-page and WAL checks serialize normal evidence writers.
When persistence fails, the broker fails closed before forwarding an operation;
a missing audit record is never treated as permission.

This is a database admission budget, **not a filesystem or host disk quota**.
The WAL can grow beyond its admission threshold by an in-flight transaction;
maintenance/VACUUM needs temporary free space. Workspace output, retained session
files, Docker storage, operator copies and backups need separate filesystem and
deployment quotas. Inspection and explicit maintenance use an uncapped connection
so an exhausted database remains inspectable and can be reclaimed. Trusted host
processes can change the database; they remain outside Ghost's threat boundary.

## Preview, then remove

```sh
ghost prune --older-than-days 30 --dry-run
ghost prune --older-than-days 30
ghost prune --older-than-days 30 --dry-run --json
```

The operator chooses 1..3650 days. Only `completed`/`failed` sessions with an older
completion time and **no pending runtime cleanup** qualify. Active, incomplete,
recent and cleanup-pending sessions remain. The same exclusive project lock as
`ghost run` prevents pruning a running project. Separate project directories can
run independently. A dry run opens/migrates the normal database schema and may
create private internal directories; it deletes no history and creates no intent.

An applied request persists its fixed cutoff before deleting anything. Session
identities must be canonical UUIDs. Deletion uses a pinned `os.Root` beneath this
database's own private sessions directory, rejects ambiguous top-level symlinks
and Linux mounts, and does not follow nested symlinks outside the session. After
directory removal, database rows and cascading events/decoys are deleted in a
transaction. Missing directories are safe to retry after a crash. The fixed
predicate survives interruption; `ghost run` resumes it **after runtime recovery
and before launching another agent**, under the project lock. It never selects
a new retention age itself.

SQLite pages are reclaimed with VACUUM and WAL truncation; blocked readers or low
disk space leave maintenance pending and cause a visible error. Close external
database readers, restore free space and retry the explicit prune or run. One
bounded receipt keeps the last completed cutoff and count. This provides logical
retention and ordinary SQLite cleanup, not guaranteed physical erasure on SSDs,
snapshots or backups, legal holds, or regulatory compliance.

## Upgrade

Stop active runs and back up `ghost.yaml` and the **whole** `.ghost` directory
together before upgrading. v0.6 adds database schema migration 5; the original
configuration and historical session identities remain intact. An old v0.5
binary refuses the newer database. Downgrade requires a consistent pre-upgrade
backup, not copying only `ghost.db` while a writer is active. Existing oversized
databases may need explicit retention or a reviewed higher budget before a new
run can proceed. Ghost never silently removes evidence to make an upgrade work.
