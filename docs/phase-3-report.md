# Phase 3 implementation report

Status: TLS/ACME infrastructure complete; protocol-specific STARTTLS state resets remain in their SMTP/IMAP phases.

## Implemented

- Pinned `tokio-rustls-acme` 0.9.1 with rustls 0.23.43 and tokio-rustls 0.26.4 using the ring provider.
- TLS-ALPN-01 listener on configurable TCP/443; IMAPS 993 and Submission 465 are not treated as challenge substitutes.
- ACME state/event polling, cached/new certificate deployment, renewal processing and sanitized PostgreSQL event records.
- PostgreSQL `CertCache` and `AccountCache` implementations encrypted with AES-256-GCM. The encryption key is supplied separately and never stored in the database.
- Dedicated-session PostgreSQL advisory lock for single-renewer operation and crash release.
- Shared ACME resolver, SNI/manual PEM resolver helpers and distinct service `ServerConfig` builders.
- `maild` with migration check, staging default, fail-closed startup, 443 listener, localhost administration HTTPS and graceful SIGINT handling.

## Migration

`202608070003_phase3_tls_acme.sql` adds encrypted cache entries and sanitized certificate lifecycle events.

## Tests

- Cache encryption round trip and tamper rejection.
- Empty certificate/key rejection.
- PostgreSQL cache persistence confirms private marker bytes do not occur in stored ciphertext.
- Two independent PostgreSQL sessions verify renewal lock exclusion and release.

## Security considerations

- Production ACME is opt-in; staging is the default.
- Normal traffic accidentally reaching the dedicated 443 ACME port is closed and never routed to the administration API.
- The administration API remains loopback-only by default and always uses TLS.
- ACME private/account keys are never logged or returned through HTTP.
- Cache AEAD keys must come from systemd credentials, container/Kubernetes secrets or an external secret manager.

## Known limitations

- ACME staging issuance requires a publicly delegated test domain and CA reachability, so it is an operator-run interoperability test rather than a hermetic workspace test.
- A lock-busy secondary node exits; follower certificate reload/notification is added when multi-node serving is deployed.
- mTLS policy and source-CIDR enforcement require peer-address/trusted-proxy configuration and remain disabled rather than partially trusted.
- SMTP/IMAP STARTTLS transitions are not present because those protocol state machines are introduced in later phases.
