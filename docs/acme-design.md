# ACME design

Verified on 2026-08-07 from official package metadata and the downloaded 0.9.1 source: `tokio-rustls-acme` 0.9.1 depends on `rustls ^0.23`, `tokio-rustls ^0.26`, Tokio, and ring; it is MIT/Apache-2.0. TLS-ALPN-01, `AcmeState`, `AcmeAcceptor`, resolver, `CertCache` and `AccountCache` signatures are compile-verified. Do not confuse it with `rustls-acme`.

Production uses the low-level resolver so SMTP/IMAP/API can share certificate material while retaining service-specific `rustls::ServerConfig`. Staging is mandatory before production. Renewal failure keeps the last valid certificate, raises metrics/alerts, and never silently serves an unrelated name.

## Listener

RFC 8737 TLS-ALPN-01 validation requires CA reachability on TCP/443. Ports 993 and 465 are not substitutes. Bind IPv4 and IPv6 where published. NAT forwards 443; load balancers/reverse proxies must pass through the ACME ALPN or terminate with an ACME-aware external manager. Kubernetes uses a dedicated Service/Ingress capability verified in staging. If 443 is unavailable, use an external certificate manager or manual certificates; unsupported challenge types are not claimed.

Multi-node mode elects one renewer using a session-level PostgreSQL advisory lock. `maild` uses a dedicated connection, so process or connection loss releases the lock. A lock-busy node fails closed; follower serving and cache notification are deferred until multi-node deployment is enabled.

## Cache comparison

| Backend | Use | Decision |
|---|---|---|
| PostgreSQL cache | multi-node, transactional/auditable | default; encrypted private/account keys |
| encrypted local cache | single node | optional; key stored separately |
| external secret manager | managed multi-node | preferred where available; adapter external |

Private/account keys are never returned by API or logged. Encryption keys are separate from DB/backups. Certificate operations are audited; expiry, attempts, failures and last success are metrics. Rate-limit responses suppress aggressive retry.
