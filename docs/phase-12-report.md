# Phase 12 report

Phase 12 implements the local authentication decision and cryptographic core.

- `mail-spf`: `ip4`, `ip6`, `a`, `mx`, `include`, `exists`, `redirect`, qualifiers, macros, recursion, DNS lookup and void budgets, and explicit None/TempError/PermError results.
- `mail-dkim`: simple/relaxed canonicalization, SHA-256 body hash, RSA-SHA256 and Ed25519 signing/verification, and bounded tag parsing.
- `mail-dmarc`: `p`, `sp`, `adkim`, `aspf`, `pct`, reporting URI parsing, strict/relaxed alignment, aggregate XML, and privacy-redacted failure reports.
- `mail-arc`: ARC set collection, contiguous instance/cv validation, chain length limit, and injected cryptographic verification.

Tests: `evaluates_ip_and_qualifiers`, `relaxed_body_and_hash_are_bounded`, `ed25519_signature_round_trip`, `parses_and_aligns_policy`, and `validates_contiguous_chain`.

DNS TXT/A/MX resolution, public-suffix organizational-domain data, and DKIM/ARC key retrieval are explicit external boundaries. They do not replace the local protocol or cryptographic decision logic.
