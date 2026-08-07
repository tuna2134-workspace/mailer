# Phase 7 report

Implemented the Phase 7 SMTP extension baseline: SIZE, PIPELINING, 8BITMIME, SMTPUTF8, enhanced status replies, DSN envelope parameters, CHUNKING/BINARYMIME, STARTTLS, TLS-only AUTH PLAIN, SCRAM-SHA-256, SCRAM-SHA-256-PLUS with TLS exporter channel binding, REQUIRETLS forwarding, DELIVERBY, and authenticated-submission-only FUTURERELEASE. EHLO only advertises configured capabilities. Submission on 587/465 enforces authentication and sender authorization; authentication alone never enables relay on port 25.

PostgreSQL migration `202608070005_phase7_extensions.sql` persists SMTP extension and SCRAM state. Migration `202608070006_delivery_timing.sql` persists release and delivery deadlines. Future release drives queue `next_attempt_at`; deliver-by drives expiry; queue leases preserve SMTPUTF8, REQUIRETLS, DSN, and DELIVERBY metadata. Raw DATA and BDAT remain bounded streaming writes.

Tests cover parser duplication and bounds, SMTP state reset, real STARTTLS, PLAIN submission, RFC 7677 SCRAM proof, SCRAM-SHA-256-PLUS exporter binding, relay denial, fixed-octet BDAT, and PostgreSQL migration/storage/lease behavior. `cargo fmt --all`, workspace tests, strict workspace Clippy, and PostgreSQL 17 container tests pass.

Security considerations: AUTH is unavailable without TLS; SCRAM proof comparison is constant-time; unknown identities perform dummy password work; database lockout complements per-session limits; sender authorization is checked before MAIL acceptance; future release is available only on authenticated submission and remains subject to normal mailbox/quota accounting; private credentials are never returned.

Known limitations: DSN message generation remains Phase 13. REQUIRETLS policy discovery/reporting remains Phase 15. OAuth/OIDC is an external authentication integration point, not an advertised SASL mechanism. AUTH LOGIN is intentionally not advertised; compatibility demand must be demonstrated before adding this weaker legacy mechanism. External MTA interoperability remains an ongoing release qualification rather than an untested conformance claim.
