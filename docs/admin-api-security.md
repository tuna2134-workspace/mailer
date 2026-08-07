# Admin API security

Default bind is `127.0.0.1:8443`; plaintext HTTP and CORS are disabled. Scoped opaque bearer tokens are initial authentication. Store only a token hash plus a non-secret lookup prefix, tenant, scopes, expiry, revoke/last-use timestamps, creator, source CIDRs and rate policy. OAuth 2.0/OIDC, mTLS and service credentials are later authentication adapters.

Tower middleware order is trusted-proxy resolution, request ID, TLS/authentication, body/concurrency/time limits, rate/source policy, authorization, handler, secure/no-store headers, then sanitized tracing/audit. Proxy headers are ignored unless the immediate peer is trusted. JSON bodies, pagination and exports have hard caps. Browser cookie authentication is not initial; if added it requires secure SameSite cookies and CSRF tokens. SQLx bound parameters, DTO field allowlists and domain validation prevent SQL injection and mass assignment.

Token secrets, passwords, SQL, stack traces and keys are redacted. Rotation permits a bounded overlap; revoke is immediate through credential version/cache invalidation. Authentication failures and rate limiting are measured and audited without secret material.
