# Phase 15 report

`mail-policy` implements bounded MTA-STS and TLS-RPT parsing, REQUIRETLS decision handling, and DANE TLSA gating. TLSA records are rejected unless the injected DNS resolver reports DNSSEC `Secure`; `Bogus` and `Indeterminate` states cannot silently enable DANE.

HTTPS retrieval/caching for MTA-STS, DNSSEC validation itself, TLSA certificate matching, and TLS-RPT aggregation are external adapters. The local policy decision never treats those unavailable inputs as verified.
