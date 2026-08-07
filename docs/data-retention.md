# Data retention

Retention is tenant policy bounded by system minimum/maximum and legal hold. Separate policies cover live mail, expunged mail, queue failures, audit events, auth events, transient spool and backups. Expunge is logical first; asynchronous purge occurs after retention and hold checks. Raw body dedupe is removed only when no live/retained references remain.

Backups age out independently; deletion responses disclose that recoverable backup copies persist until backup expiry. Audit events use longer retention and contain identifiers/metadata, not message bodies or secrets. Purge jobs are idempotent, rate-limited and audited.

