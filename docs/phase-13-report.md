# Phase 13 report

Implemented `mail-dsn` with bounded RFC 3464 `multipart/report` failure and delay report construction, `message/delivery-status` fields, `Auto-Submitted`, `Original-Envelope-Id`, `Original-Recipient`, `Remote-MTA`, and enhanced status validation. RFC 8098 MDN construction is provided with `message/disposition-notification`.

Permanent queue failures now use the DSN builder inside the existing atomic PostgreSQL delivery transaction and retain the null reverse-path behavior. Header injection and oversized diagnostics are rejected. Original message content is excluded by the current privacy/backscatter policy.

External policy inputs remain explicit: consent, duplicate-notification suppression, SMTPUTF8 envelope negotiation, and report rate limiting belong to the caller/queue policy layer.
