# Phase 12 report

Phase 12 implements the local authentication decision and cryptographic core.

- `mail-spf`: `ip4`, `ip6`, `a`, `mx`, `ptr`, `include`, `exists`, `redirect`, qualifiers, RFC macro transformers including validated `%{p}`, recursion, DNS/void budgets, and explicit result/error mapping.
- `mail-dkim`: simple/relaxed canonicalization, repeated-header selection, SHA-256 body hash, RSA-SHA256 and Ed25519 signing/verification, signature lifetime/body length, and validated DNS key records.
- `mail-dmarc`: RFC 9989 `p`, `sp`, `np`, `t`, `psd`, strict/relaxed alignment, bounded DNS Tree Walk integration, and structured requested disposition. Historic `pct` is ignored. RFC 9990/9991 report helpers remain explicitly partial.
- `mail-arc`: ARC set collection, required/duplicate tag checks, contiguous instance/cv validation, chain length limit, algorithm-compatible DNS keys, newest AMS, and all-seal cryptographic verification.

Tests include `unknown_mechanism_and_malformed_cidr_are_permanent_errors`, `validated_domain_macro_uses_forward_confirmed_ptr_name`, `repeated_headers_are_selected_once_each_from_the_bottom`, `subdomain_nonexistent_and_testing_policies_are_applied`, and `validates_contiguous_chain`.

DNS resolution and DKIM/ARC key publication are external boundaries. Internet interoperability and complete DMARC reporting are not inferred from unit tests.
