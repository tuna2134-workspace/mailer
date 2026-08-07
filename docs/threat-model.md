# Threat model

Protected assets: message confidentiality/integrity/availability, credentials, tenant boundaries, queue correctness, signing/certificate keys, audit history and PostgreSQL recovery data. Attackers include unauthenticated Internet peers, compromised users/tokens, malicious tenant admins, poisoned DNS/upstreams and insiders.

| Threats | Controls |
|---|---|
| open relay, sender spoofing, backscatter | default-deny relay, recipient verification, authz, SPF/DKIM/DMARC, null-path DSNs |
| SMTP smuggling, splitting, CRLF/header injection, parser differential | one strict framing parser, bare-LF policy, reject ambiguous terminators, raw-byte tests/fuzzing |
| slowloris, connection/queue/DB/disk/inode exhaustion | deadlines, per-IP/tenant limits, bounded buffers/spool, pool admission, quotas/backpressure |
| MIME/zip bombs, nesting, huge headers/recipients/literals | byte/line/header/part/depth/decompression/count limits; scanners sandboxed externally |
| auth brute force/credential stuffing/token leakage | TLS-only, Argon2id, rate limit/lockout, token hashing/rotation/revoke, redaction |
| TLS downgrade/STARTTLS stripping/key leakage | submission/access require TLS, MTA policy reporting, encrypted keys, least privilege, expiry alerts |
| DNS poisoning/rebinding/SPF amplification/SSRF | validating resolver state, response binding, lookup budgets, network egress policy, no arbitrary URL fetch |
| mail/bounce/alias/Sieve redirect loops | hop/depth/visited sets, Auto-Submitted, null reverse-path, redirect/generated-message budgets |
| path traversal/symlink/spool plaintext | no user paths, exclusive no-follow temp files, 0700, encryption/short retention, reconciliation |
| Unicode confusable/IDN homograph/malformed UTF-8 | preserve canonical identity, IDNA/normalization policy, display warnings, byte-safe parsing |
| admin abuse, tenant escape, privilege escalation, mass assignment | scoped roles, field allowlists, tenant-bound commands/FKs, OCC, idempotency, audit |
| log injection/secret or private-key leakage | structured fields, control escaping, high-cardinality bans, secret types/redaction, no key APIs |
| PostgreSQL failure/data loss | constraints/transactions, bounded retries, PITR, restore drills, readiness fail-closed |

Residual risks: SMTP remote delivery is not exactly-once; external DNS/CA/scanner availability; traffic analysis; endpoint compromise; accepted malformed legacy mail. Each Phase performs an abuse-case review before completion.

