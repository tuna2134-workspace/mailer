# Testing strategy

Each implemented normative requirement maps `RFC/section -> code -> runnable test` under `docs/conformance/`. Status stays partial until tests pass. Small unit tests cover pure invariants; transcript tests cover protocol framing/state; negative/property/fuzz corpus tests target arbitrary splits and malformed bytes; PostgreSQL Testcontainers cover actual constraints, transactions and recovery. SQLite is never substituted.

Phase gates run fmt, clippy, unit/integration tests, PostgreSQL contract tests, example config, docs/matrix/conformance update and security review. High-risk suites cover SMTP smuggling, streaming/literal limits, alias/Sieve loops, UID/MODSEQ/quota races, `SKIP LOCKED` leases and worker crash, migrations/rollback/deadlock, DB outage, large body, backup restore, ACME staging/renewal/cache/SNI/redaction, API authz/tenant isolation/idempotency/OCC/rate/body caps, and IMAP sequence shifts/concurrent sessions/QRESYNC.

Fuzz targets are added when parsers appear, not as empty Phase 0 scaffolding. Interoperability tests record product/version and transcript with secrets removed. Benchmarks establish limits; they are not conformance evidence.

