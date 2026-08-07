# Phase 7 report

Implemented SIZE, PIPELINING advertisement, 8BITMIME, enhanced status replies, STARTTLS, TLS-only AUTH PLAIN, CHUNKING, and BINARYMIME. EHLO capabilities are derived from runtime availability. STARTTLS uses the shared ACME certificate resolver and resets SMTP state. BDAT streams fixed-size chunks to PostgreSQL without buffering the message. Authentication supports primary and application-password Argon2 hashes, three attempts per connection, and a database-backed five-failure/15-minute lockout.

Relevant specifications are RFC 1870, RFC 2920, RFC 3030, RFC 3207, RFC 3461, RFC 4616, RFC 4954, RFC 6152, RFC 6531, and RFC 8689. Changed crates are `mail-smtp-proto`, `mail-smtp-server`, `mail-storage`, `mail-postgres`, and `maild`. No migration or API endpoint was added. Tests cover extension parsing, duplicate rejection, STARTTLS state reset/AUTH gating, PLAIN decoding, exact-octet BDAT streaming, relay denial, and timeout handling.

Security: AUTH is neither advertised nor accepted before TLS; password verification runs outside Tokio workers; unknown accounts receive dummy Argon2 work; failures are rate-limited and locked; BDAT and command sizes are bounded; authenticated sessions do not gain relay permission.

Known limitations: DSN parameters are parsed but DSN is not advertised because persistence is absent. SMTPUTF8 and REQUIRETLS are parsed but not advertised because end-to-end policy is incomplete. SCRAM-SHA-256, SCRAM-SHA-256-PLUS, channel binding, DELIVERBY, and FUTURERELEASE remain unimplemented. STARTTLS needs a live-certificate integration test before RFC 3207 can be marked full.
