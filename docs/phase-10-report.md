# Phase 10 report

## Implemented

- IMAP4rev2 mailbox commands: `SELECT`, `EXAMINE`, `CREATE`, `DELETE`, `RENAME`, `SUBSCRIBE`, `UNSUBSCRIBE`, `LIST`, `LSUB`, `STATUS`, `NAMESPACE`, `CLOSE`, `UNSELECT`, and `CHECK`.
- Message commands: `APPEND`, `FETCH`, `STORE`, `SEARCH`, `COPY`, `MOVE`, `EXPUNGE`, `UID FETCH`, `UID STORE`, `UID SEARCH`, `UID COPY`, `UID MOVE`, and `UID EXPUNGE`.
- PostgreSQL-backed subscriptions, raw-message APPEND, sequence-number projection, UID allocation, flags/MODSEQ mutation, quota enforcement, atomic COPY/MOVE, and atomic EXPUNGE.
- `UIDPLUS`, `MOVE`, `NAMESPACE`, and `LITERAL+` are advertised only with their implemented command paths.
- Recoverable malformed commands now receive a tagged `BAD`; an unsafe or unavailable tag receives untagged `BAD` without reflecting CR/LF.

## RFC and sections

- RFC 9051 sections 6.3, 6.4, and 7 (mailbox/message commands and responses).
- RFC 4315 (`UIDPLUS`) and RFC 6851 (`MOVE`), partial as recorded in the conformance file.

## Changed files

- `crates/mail-imap-proto/src/parser.rs`, `session.rs`, and `lib.rs`
- `crates/mail-imap-server/src/lib.rs` and `commands.rs`
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
- APPEND remains bounded by the configured literal limit and never accepts an unframed message body.
- COPY/MOVE and EXPUNGE lock affected rows and commit atomically; database constraints remain the final UID/quota authority.
- Read-only `EXAMINE` rejects STORE, MOVE, and EXPUNGE and does not set `\\Seen` during FETCH.

## Known limitations

- SEARCH currently implements `ALL`, `SEEN`, `UNSEEN`, `DELETED`, and `UNDELETED`; the remaining RFC 9051 search keys are not implemented and return tagged `BAD`.
- FETCH returns raw full-message data for BODY/RFC822 requests and supports byte partials, but section-specific MIME extraction and a complete ENVELOPE/BODYSTRUCTURE serializer remain unimplemented.
- APPEND flags and client-supplied INTERNALDATE are not yet accepted. APPEND is bounded by the listener literal limit (64 KiB by default), so large-literal database streaming remains pending.
- STORE applies a multi-message set as individually atomic mutations; command-wide rollback is pending.
- Expunged-message garbage collection and tenant physical-byte reclamation remain the deletion-workflow responsibility.

## Next

Complete the listed Phase 10 conformance gaps before Phase 11 synchronization (`IDLE`, `CONDSTORE`, and `QRESYNC`).
