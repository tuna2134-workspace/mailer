# Security model

Defaults: no relay before authorization; local recipients only on port 25; AUTH only over TLS on submission/IMAP; admin API binds localhost and requires HTTPS; CORS deny; secrets never appear in responses/logs/config examples. Deny unknown capabilities and do not advertise unavailable extensions.

Every trust boundary has byte/count/depth/time/concurrency limits. Parsers operate on arbitrary bytes without panic. Library crates forbid `unwrap`/`expect` by lint/review. Passwords use Argon2id with versioned parameters; API/application passwords are hashed, scoped, expiring/revocable, source-network constrained and rate-limited. Authentication events and administrative mutations are audited.

Workspace code forbids `unsafe`, but reviewed dependencies may contain unsafe implementations. The security-sensitive boundary is intentionally small: rustls/ring handle TLS and cryptography, SQLx handles PostgreSQL framing and bound queries, Hickory handles DNS, and Argon2 handles password hashing. `cargo audit` checks RustSec advisories; `cargo deny` enforces licenses and approved registries, monitors wildcard/duplicate dependencies, and prevents accidental OpenSSL/native-tls transport dependencies. A passing dependency check is not a claim that transitive unsafe code has been formally verified.

`RUSTSEC-2023-0071` is narrowly ignored because `rsa 0.9.10` is present only as an optional `sqlx-mysql` lockfile entry: this workspace disables SQLx default features, enables PostgreSQL only, and `cargo tree -i rsa@0.9.10` is empty. Mail DKIM RSA operations use ring, not the RustCrypto `rsa` crate. Remove the exception immediately if `rsa` enters the resolved build graph. Hickory is pinned at 0.26.1 or newer to include the fixes for `RUSTSEC-2026-0118` and `RUSTSEC-2026-0119`.

Tenant identity comes from the authenticated principal, never a request-selected tenant alone. Application authorization precedes repositories; composite FKs/RLS evaluation in Phase 1 provide defense in depth. Error responses use RFC 9457 and redact SQL/schema/stack data. Private keys are encrypted with separately managed keys.
