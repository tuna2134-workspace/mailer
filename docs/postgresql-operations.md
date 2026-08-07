# PostgreSQL operations and migrations

Production defaults to `[database.migrations] mode = "check"`; modes are `disabled`, `check`, `auto`. `mail-migrate` is the explicit operator path. Startup checks schema compatibility before listeners become ready.

Phase 1 pins SQLx 0.8.6 because the workspace MSRV is 1.85; SQLx 0.9.0 declares Rust 1.94. The pin must be re-evaluated with dependency advisories before each release.

Migrations use SQLx, are immutable after release, audited by version/checksum/operator, transactional where PostgreSQL permits, and follow expand-and-contract: add nullable/new objects, dual-compatible deploy/backfill in bounded batches, switch reads/writes, then remove only after a backup and compatibility window. CI rejects obvious destructive DDL unless an approved migration note exists. Large indexes use an explicit non-transactional operational step such as concurrent creation, with resumable status.

Pool limits reserve capacity for migration/operations. Set application name, acquire/statement/lock/idle-in-transaction timeouts. Retry only classified serialization/deadlock failures with bounded jitter; never blindly retry arbitrary transactions. Readiness fails when durable writes or schema compatibility fail. Replica reads are not used for correctness-sensitive mailbox/queue state until a lag policy exists.
