# Phase 17 report

`mail-mime` now recognizes S/MIME enveloped-data, S/MIME signed-data and multipart signatures, plus OpenPGP/MIME encrypted and signed multipart structures. Recognition reuses the existing bounded MIME parser, so message size, nesting depth, part count, boundary size, and decoded-output limits apply before any cryptographic provider is invoked.

RFC 2231 extended and continued parameter values are decoded with bounded continuation count and strict percent decoding while preserving arbitrary bytes. Charset conversion is deliberately separate.

CMS/OpenPGP cryptographic operations, certificate validation, trust decisions, private-key custody, revocation, hardware-token access, and user-facing key lifecycle are external provider boundaries. Raw PostgreSQL message bytes remain authoritative, and a failed crypto operation cannot mutate the stored message.
