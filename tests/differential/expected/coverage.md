# Differential coverage inventory

`NOT_COMPARABLE` means the current reference configuration cannot provide equivalent semantics;
it is not a passing test.

| Protocol | Cases | Status | Reason |
|---|---|---|---|
| SMTP | AUTH PLAIN/SCRAM, authorized submission | NOT_COMPARABLE | Reference Postfix SASL backend is deliberately absent |
| SMTP | BDAT cumulative message-size overflow | NOT_COMPARABLE | Targets do not expose an equivalent configurable limit |
| SMTP | accepted-message state extraction | NOT_COMPARABLE | Postfix sink intentionally discards accepted content |
| IMAP | simultaneous-session mutation | NOT_COMPARABLE | Needs a two-connection barrier driver |
| IMAP | QRESYNC/VANISHED | NOT_COMPARABLE | Compare only after capability intersection and state seeding |
| IMAP | oversized/partial literals | NOT_COMPARABLE | Target limits differ; needs per-target expected-limit metadata |

Promote an entry only with a raw protocol case, state invariant, and RFC adjudication.
