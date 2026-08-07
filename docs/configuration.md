# Configuration

TOML config covers hostname, tenants/local domains, SMTP/submission/IMAP/ACME/admin listeners, PostgreSQL pool/migration mode, certificate source, relay/auth/queue limits, message/recipient/time limits, DNS/DNSSEC, outbound source/TLS, DKIM/SPF/DMARC/ARC, MTA-STS/DANE, logging/metrics and scanner integrations.

Defaults are fail-closed: admin localhost+TLS, submission/IMAP require TLS, no authenticated relay until policy grants it, production migrations `check`, bounded sizes/timeouts, ACME staging for examples. Unknown keys and invalid/conflicting listeners are errors. Secrets are references (`env`, systemd credential, Docker/Kubernetes secret, secret-manager URI, inherited FD), not required plaintext values. Environment overrides are explicit allowlisted paths.

```toml
[database]
url_secret = "systemd:maild-database-url"
min_connections = 5
max_connections = 100
acquire_timeout_seconds = 10
statement_timeout_seconds = 30
application_name = "maild"
[database.migrations]
mode = "check"

[acme]
enabled = true
directory = "letsencrypt-staging"
challenge = "tls-alpn-01"
listen = ["0.0.0.0:443", "[::]:443"]
cache_backend = "postgres"
distributed_lock = true

[smtp]
listen = ["0.0.0.0:25", "[::]:25"]
[submission]
listen = ["0.0.0.0:587", "[::]:587"]
require_starttls = true
[submissions]
listen = ["0.0.0.0:465", "[::]:465"]
[imap]
listen = ["0.0.0.0:143", "[::]:143"]
require_starttls = true
[imaps]
listen = ["0.0.0.0:993", "[::]:993"]
[admin_api]
listen = ["127.0.0.1:8443"]
require_tls = true
cors = "deny"
```

## Phase 3 executable environment

`maild` currently accepts secret-capable environment inputs while the typed TOML loader remains scheduled with the wider listener configuration:

- `MAIL_DATABASE_URL`: PostgreSQL URL (required).
- `MAIL_ACME_DOMAINS`: comma-separated DNS names (required).
- `MAIL_ACME_CONTACTS`: comma-separated `mailto:` contacts (required).
- `MAIL_ACME_CACHE_KEY_HEX`: separate 32-byte AES key encoded as exactly 64 hex characters (required; never stored in PostgreSQL).
- `MAIL_ACME_PRODUCTION=true`: use Let's Encrypt production; omitted means staging.
- `MAIL_ACME_LISTEN`: TLS-ALPN-01 address, default `0.0.0.0:443`.
- `MAIL_ADMIN_LISTEN`: administration HTTPS address, default `127.0.0.1:8443`.
- `MAIL_HOSTNAME`: SMTP server identity; defaults to the first ACME domain and is strictly validated.
- `MAIL_SMTP_LISTEN`: inbound SMTP address, default `0.0.0.0:25`.

Run `mail-migrate up` explicitly first. `maild` only checks migration compatibility and fails closed on mismatch.
