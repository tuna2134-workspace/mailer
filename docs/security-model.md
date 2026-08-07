# Security model

Defaults: no relay before authorization; local recipients only on port 25; AUTH only over TLS on submission/IMAP; admin API binds localhost and requires HTTPS; CORS deny; secrets never appear in responses/logs/config examples. Deny unknown capabilities and do not advertise unavailable extensions.

Every trust boundary has byte/count/depth/time/concurrency limits. Parsers operate on arbitrary bytes without panic. Library crates forbid `unwrap`/`expect` by lint/review. Passwords use Argon2id with versioned parameters; API/application passwords are hashed, scoped, expiring/revocable, source-network constrained and rate-limited. Authentication events and administrative mutations are audited.

Tenant identity comes from the authenticated principal, never a request-selected tenant alone. Application authorization precedes repositories; composite FKs/RLS evaluation in Phase 1 provide defense in depth. Error responses use RFC 9457 and redact SQL/schema/stack data. Private keys are encrypted with separately managed keys.

