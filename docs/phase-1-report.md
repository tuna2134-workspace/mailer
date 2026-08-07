# Phase 1 implementation report

## Implemented

- Rust 2024 workspace with MSRV 1.85 and forbidden unsafe/library unwrap/expect lints.
- Domain IDs and validated domain/local-part/quota values; tenant, domain, user, alias, mailbox and queue entities.
- Shared repository contract and application administration service.
- PostgreSQL repository for tenant/domain/user/alias/mailbox creation, atomic quota consumption, UID/MODSEQ allocation and queue leasing.
- SQLx migration and explicit `mail-migrate up|check` binary.
- In-memory test repository for fast contract behavior; it is not a durable or integration-test substitute.

## Migration

`202608070001_phase1.sql` creates tenants, domains, users/credentials, aliases/targets, mailboxes, immutable raw `BYTEA` messages, mailbox-message state, per-recipient queue/attempts, audits, ingestions and API tokens. Composite tenant foreign keys, UID uniqueness, quota checks and lease consistency are database constraints.

## Tests

- domain normalization and bounded local-part tests;
- in-memory UID/MODSEQ monotonicity and quota rejection;
- PostgreSQL 17 migration/constraint test;
- concurrent PostgreSQL UID/MODSEQ allocation;
- PostgreSQL quota conditional update;
- PostgreSQL `SKIP LOCKED` queue lease exclusion.

The PostgreSQL test is environment-gated for ordinary `cargo test`, and was also executed against a fresh disposable PostgreSQL 17 container with `MAIL_TEST_DATABASE_URL` set.

## Security and correctness

No protocol or untrusted-message parser was added. SQL uses bound parameters. Tenant-crossing references are blocked where aggregate relations are known. Raw messages are immutable rows. Queue network work is designed to occur after the lease transaction. The migration CLI reads its URL from a secret-capable environment rather than requiring a command-line secret.

## Known limitations

- Phase 1 is a foundation, not a complete administration product: password hashing, roles, audit-writing services, deletion workers and body streaming ingestion arrive in their owning phases.
- Alias graph loop detection needs the Phase 2 application command/transaction; only structural storage exists now.
- In-memory testkit queue leasing is intentionally empty; PostgreSQL is the authoritative concurrency implementation.
- Domain/local-part validation is conservative ASCII. Full RFC 5322/SMTPUTF8/IDNA parsing belongs to Phase 6/7.
- Migration rollback is restore/forward-fix; no destructive down migration is supplied.
- PostgreSQL integration requires Docker or an explicit test database; the ordinary test skips it when the environment variable is absent.

## Standards impact

No SMTP, IMAP or MIME RFC behavior is claimed implemented. This phase establishes storage invariants needed by RFC 9051 UID/UIDVALIDITY/MODSEQ work, but conformance status remains `not implemented` until protocol code and mapped tests exist.
