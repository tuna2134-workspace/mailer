# Architecture (Phase 0)

The system is a Tokio Rust workspace. Protocol adapters depend inward on application ports; `mail-application` owns use cases, authorization and transaction boundaries; `mail-domain` contains pure invariants; PostgreSQL is the only durable store. API and CLI never duplicate business rules, and `mailctl` normally calls the API.

```text
SMTP / Submission / LMTP / IMAP / Admin API
                 |
          mail-application
       / domain ports | policies \
 mail-domain      mail-message/mailbox/queue
                 |
            mail-postgres
                 |
             PostgreSQL
```

Planned workspace follows the requested crate list. Crates are created only when their Phase starts; empty scaffolding has no value. No `mail-pop3` crate will exist. Binaries are `maild`, `mailctl`, `mail-queue-worker`, and `mail-migrate`.

Key boundaries:

- Protocol crates parse/serialize bytes and expose bounded incremental events; they do not query SQL.
- Application commands carry authenticated actor, tenant, request/idempotency IDs, and invoke repository transactions.
- Domain identifiers are UUID newtypes; tenant ID is explicit on every tenant-owned aggregate.
- PostgreSQL constraints are the final authority for uniqueness and monotonic state.
- Message bytes remain immutable; delivery/mailbox relations and flags are mutable metadata.
- TLS certificate source is shared; each service owns a distinct `rustls::ServerConfig`.
- CPU-heavy password/crypto work uses bounded blocking workers; I/O remains async. No lock guard crosses `.await`.
- `unsafe` is forbidden at workspace lint level unless a narrowly reviewed exception document exists.

Initial dependency decisions are deferred until the owning Phase and verified from official manifests. Rust edition 2024 and MSRV 1.85 are the initial workspace policy; dependency MSRV may force a documented increase.

