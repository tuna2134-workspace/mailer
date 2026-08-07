# Delivery queue design

One message has per-recipient queue state so partial success is durable. Workers claim eligible recipients in a short transaction using `FOR UPDATE SKIP LOCKED`, set a random lease owner and expiry, commit, perform network I/O without a DB lock, then conditionally record the result only if the lease token still matches. Lease renewal is bounded; expiry enables crash recovery.

Phase 5 classifies DNS and SMTP 4xx/5xx results, applies deterministic exponential backoff with bounded jitter and a queue expiry, and stores bounded diagnostics. Permanent failures create one minimal notification with a null reverse-path and `Auto-Submitted: auto-generated`; RFC 3464 multipart DSNs, aggregation, hop checks and policy-based backscatter suppression remain Phase 13.

The initial worker is deliberately sequential, which is a safe per-domain/per-host limit of one. Add keyed semaphores only after measurements justify parallel delivery. Queue pause/API controls remain pending. Exactly-once SMTP delivery is impossible; lease recovery provides at-least-once attempts and may redeliver after an ambiguous disconnect.
