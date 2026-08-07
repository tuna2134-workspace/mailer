# Phase 2 implementation report

Status: complete for the Phase 2 administration boundary. TLS listeners and certificate handling remain Phase 3.

## Implemented features

- Axum `/api/v1` tenant, domain, user, alias, quota, mailbox-administration, application-password, API-token and audit endpoints.
- Item create/read/update/delete or lifecycle operations, including user/domain enable/disable, user unlock/password rotation, domain DNS guidance/verification request, and mailbox rename/delete.
- Opaque scoped bearer tokens. Only SHA-256 token hashes are persisted; token secrets are returned once. Expiry, revocation and allowed-source-network metadata are stored.
- Role/scope authorization, system-versus-tenant administration, and not-found masking for cross-tenant resources.
- Argon2id password and application-password hashing on bounded blocking tasks. Secrets are input-only or one-time output.
- `If-Match` optimistic concurrency for mutable resources.
- Required `Idempotency-Key` on POST, request-hash conflict detection and completed-response replay.
- Pre-mutation audit-attempt persistence plus operation-specific success events.
- RFC 9457 `application/problem+json`, sanitized details, stable error codes and per-response `X-Request-Id`.
- Bounded offset cursor pages (`limit` 1–200), 64 KiB bodies, 30 second timeout, concurrency limit, fixed-window per-token rate limiting, no-store/nosniff headers, CORS deny-by-absence and sensitive Authorization marking.
- Reqwest/rustls administration client and resource-oriented `mailctl`; API token comes from `MAIL_API_TOKEN`, while JSON/secrets are accepted through bounded stdin rather than command arguments.

## Related specifications

- RFC 9457, Sections 3 and 3.1: Problem Details response representation.
- OpenAPI 3.1: [mail-admin-api.yaml](../openapi/mail-admin-api.yaml).
- Authentication, authorization, tenant isolation and idempotency are product security contracts, not claimed as IETF mail-protocol conformance.

## Changed components

- `mail-storage`: repository contracts and administration projections.
- `mail-application`: use cases, authorization, alias-loop validation and transaction-facing orchestration.
- `mail-postgres`: parameterized PostgreSQL implementations, OCC and lifecycle operations.
- `mail-admin-api`: HTTP routes and security middleware.
- `mail-admin-client`, `mailctl`: HTTPS client and operator commands.
- `mail-testkit`: shared in-memory contract fixture.
- `202608070002_phase2_admin.sql`: roles, bindings, idempotency and administration indexes.

## Tests

- Workspace format, Clippy with warnings denied, and all workspace tests pass.
- API tests cover unauthenticated access, RFC 9457 content type, request ID, scope and tenant isolation, POST replay, and page continuation.
- PostgreSQL 17 contract test covers migrations, authentication, audit, CRUD/OCC, passwords, application passwords, API tokens, idempotency, mailbox state, UID/MODSEQ/quota concurrency and queue leases.
- PostgreSQL-backed API test covers tenant/domain CRUD, stale `If-Match`, and idempotent replay.

## Security considerations and limits

- The router does not open a plaintext socket. HTTPS binding, mTLS, trusted-proxy interpretation and runtime enforcement of token source CIDRs belong to the Phase 3 TLS listener; source CIDRs are already validated by PostgreSQL and retained on tokens.
- The rate limiter is process-local. Replace it with a shared limiter only when multiple API nodes require a global quota.
- Cursor pagination uses a numeric offset; use keyset cursors if large administration tables make offset cost measurable.
- Audit attempts are fail-closed before mutation, but audit and resource writes are not one database transaction. Operation-specific success events distinguish successful changes.
- DNS verification is an accepted asynchronous request in Phase 2; resolver-backed verification is implemented with the DNS layer in later phases.
- DKIM records cannot be emitted until a signing key exists; the endpoint must not invent key material.

No SMTP, IMAP, MIME or mail-authentication protocol conformance is claimed by this phase.
