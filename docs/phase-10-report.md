# Phase 10 report

## Implemented

- IMAP4rev2 mailbox commands: `SELECT`, `EXAMINE`, `CREATE`, `DELETE`, `RENAME`, `SUBSCRIBE`, `UNSUBSCRIBE`, `LIST`, `LSUB`, `STATUS`, `NAMESPACE`, `CLOSE`, `UNSELECT`, and `CHECK`.
- Message commands: `APPEND`, `FETCH`, `STORE`, `SEARCH`, `COPY`, `MOVE`, `EXPUNGE`, `UID FETCH`, `UID STORE`, `UID SEARCH`, `UID COPY`, `UID MOVE`, and `UID EXPUNGE`.
- PostgreSQL-backed subscriptions, streaming raw-message APPEND, sequence-number projection, UID allocation, flags/MODSEQ mutation, quota enforcement, atomic COPY/MOVE, and atomic EXPUNGE.
- `UIDPLUS`, `MOVE`, `NAMESPACE`, and `LITERAL+` are advertised only with their implemented command paths.
- Recoverable malformed commands now receive a tagged `BAD`; an unsafe or unavailable tag receives untagged `BAD` without reflecting CR/LF.

## RFC and sections

- RFC 9051 sections 6.3, 6.4, and 7 (mailbox/message commands and responses).
- RFC 4315 (`UIDPLUS`) and RFC 6851 (`MOVE`) for the Phase 10 command set.

## Changed files

- `crates/mail-imap-proto/src/parser.rs`, `session.rs`, and `lib.rs`
- `crates/mail-imap-server/src/lib.rs`, `commands.rs`, `commands/fetch.rs`, and `commands/search.rs`
- `crates/mail-storage/src/lib.rs`
- `crates/mail-postgres/src/lib.rs` and `imap.rs`
- `migrations/202608070009_phase10_imap.sql`
- `crates/mail-postgres/tests/postgres_imap.rs`

## Migration

- Added `imap_subscriptions`, keyed by user and mailbox with cascading cleanup.

## Tests

- Parser coverage for UID FETCH, APPEND literals, MOVE, sequence sets, quotes, and literal framing.
- Command helper coverage for LIST wildcard semantics and partial FETCH ranges.
- PostgreSQL 17 integration coverage for mailbox creation/subscription, APPEND, UID allocation, FETCH backing data, STORE/MODSEQ, COPY/quota, and EXPUNGE.

## Security considerations

- Every PostgreSQL operation derives mailbox ownership from the authenticated user ID.
- APPEND remains bounded by the configured literal limit, uses an unlinked `0600` temporary spool above 64 KiB, and writes PostgreSQL ingestion chunks without loading the message into memory.
- COPY/MOVE and EXPUNGE lock affected rows and commit atomically; database constraints remain the final UID/quota authority.
- Read-only `EXAMINE` rejects STORE, MOVE, and EXPUNGE and does not set `\\Seen` during FETCH.

## Known limitations outside the Phase 10 scope

- `$` is part of the separately scheduled SEARCHRES extension and is not advertised.
- Legacy `\Recent` behavior is intentionally absent from IMAP4rev2; IMAP4rev1 clients receive compatibility capability support without a false `\Recent` claim.
- Expunged-message physical garbage collection remains the deletion/retention workflow's responsibility; logical mailbox quota is released atomically by EXPUNGE.

## Next

Phase 10 is complete. Phase 11 synchronization is implemented in `docs/phase-11-report.md`.
