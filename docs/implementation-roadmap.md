# Implementation roadmap

Phase 0 is documentation only. Later phases follow the requested 1-17 ordering; no phase is complete without its quality gates.

## Phase 1 status

The storage foundation is implemented; see `docs/phase-1-report.md`. Protocol conformance remains unclaimed.

Phase 2 is complete for the administration boundary; see `docs/phase-2-report.md`. Phase 3 TLS/ACME infrastructure is implemented; see `docs/phase-3-report.md`. Protocol-specific STARTTLS wiring follows the SMTP and IMAP phases.

Phase 4 SMTP receiving and transactional local delivery are implemented; see `docs/phase-4-report.md`. SMTP sending and queue processing remain Phase 5.

Phase 5 SMTP routing, sending and queue processing are implemented as a bounded baseline; see `docs/phase-5-report.md`. Outbound STARTTLS belongs to Phase 7 and advanced TLS policy to Phase 15.

Phase 6 bounded IMF, address and MIME parsing is implemented as a partial RFC baseline; see `docs/phase-6-report.md`. Unsupported obsolete/EAI/RFC 2231 forms remain explicit rather than silently normalized.

Phase 7 SMTP extensions, TLS-only authentication, authenticated submission, and extension queue propagation are implemented; see `docs/phase-7-report.md`.

Phase 8 mailbox storage state, UID/UIDVALIDITY/MODSEQ allocation, flags, expunge tombstones, quota accounting, and concurrent mutation control are implemented; see `docs/phase-8-report.md`. IMAP wire and sequence-number behavior begins in Phase 9.

Phase 9 IMAP4rev2 framing, parser/serializer, connection states, STARTTLS/implicit TLS, TLS-only authentication, and basic commands are implemented; see `docs/phase-9-report.md`.

Phase 10 is complete with PostgreSQL-backed mailbox/message operations, sequence/UID separation, UIDPLUS responses, SEARCH, nested MIME FETCH, extended BODYSTRUCTURE, streaming APPEND, atomic STORE, COPY/MOVE, and EXPUNGE; see `docs/phase-10-report.md`.

Phase 11 is complete with IDLE, CONDSTORE, QRESYNC, CHANGEDSINCE, UNCHANGEDSINCE/MODIFIED, HIGHESTMODSEQ, VANISHED, durable reconnect synchronization, and PostgreSQL-backed cross-session notifications; see `docs/phase-11-report.md`.

## Phase 1 detailed plan

1. Create only domain/application/storage/PostgreSQL/migration/testkit crates and migration binary.
2. Define tenant/domain/user/alias/mailbox/queue newtypes, invariants and domain errors; forbid unsafe and library unwrap/expect.
3. Define application service ports and commands carrying actor, tenant, request/idempotency and transaction context.
4. Add SQLx migrations for tenancy, identities, aliases, mailbox counters, immutable messages, queue recipient leases, audit and ingestion state.
5. Implement PostgreSQL repositories and one transaction coordinator; no API/protocol adapters yet.
6. Add the same contract suite for a minimal in-memory repository and real PostgreSQL Testcontainer; only PostgreSQL is durable/integration authority.
7. Race tests: UID/MODSEQ monotonic allocation, quota conditional update, alias snapshot/loop checks, queue `SKIP LOCKED`, deletion-versus-delivery, orphan reconciliation.
8. Add `mail-migrate`, schema compatibility check, sample config validation, operations/rollback notes, and Phase 1 conformance updates.

Exit: all requested gates that are applicable to Phase 1 pass. Fuzzing is not fabricated for code with no parser; the first parser phase adds its real target.

## Risks, unknowns, external dependencies

- SMTPbis and other active drafts may publish during development; only published RFCs alter the baseline after review.
- `tokio-rustls-acme` 0.9.1 APIs, rustls 0.23 and tokio-rustls 0.26 compatibility were verified by compiling the custom PostgreSQL cache and low-level acceptor integration.
- PostgreSQL `BYTEA` streaming ergonomics and acceptable WAL/replica lag require measurement with configured maximum message sizes.
- SQLx/dependency versions, licenses, MSRV, unsafe footprint, advisories, features and parser limits remain unselected until Phase ownership; no guessed pins.
- DNSSEC validation semantics vary by resolver; DANE is not enabled until authenticated-state propagation is proven.
- PSL lifecycle, DMARC report privacy, scanner/OIDC/secret-manager APIs and multi-node ACME reload are external dependencies.
- SMTP delivery cannot guarantee exactly once across ambiguous network failure.
- Full S/MIME/OpenPGP key management and a mailing-list product are outside the core server boundary.
