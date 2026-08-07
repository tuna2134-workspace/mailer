# RFC conformance records

No protocol feature is implemented in Phase 0. Before implementation, create `rfcNNNN.md` records with one normative requirement per entry:

```text
RFC: RFC XXXX
Section: X.Y
Requirement: MUST ...
Implementation: crates/...
Test: test_...
Status: implemented / partial / not implemented
Notes: ...
```

Only RFC text and verified errata may supply requirement wording. A feature without a passing mapped test remains `partial` or `not implemented`.
