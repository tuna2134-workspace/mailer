# TLS listener design

Listeners: SMTP 25 STARTTLS/opportunistic, Submission 587 STARTTLS-required, Submission 465 implicit TLS, IMAP 143 STARTTLS-required by default, IMAPS 993 implicit TLS, HTTPS admin 8443 TLS-required, ACME 443 TLS-ALPN-01. Cleartext authentication is forbidden.

A shared certificate provider resolves SNI to immutable certified-key snapshots. Each service has its own rustls config, ALPN list, client-auth policy, timeout and cipher policy. Reload swaps snapshots; existing sessions continue. Unknown SNI follows an explicit default-name policy or fails—never leaks another tenant's certificate accidentally. STARTTLS parsers reject pipelined plaintext after the upgrade boundary and reset protocol state as specified.

Manual certificate and external-manager modes remain available. Cryptographic provider selection is pinned and tested in Phase 3; the requested crate currently documents ring, while other providers are `unverified` for it.

