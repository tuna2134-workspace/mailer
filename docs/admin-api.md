# Administration API

Base path `/api/v1`, JSON over HTTPS, OpenAPI 3.1. Initial resources: tenants, domains, users, aliases, mailboxes/quotas, queue, certificates/ACME and audit. Handlers validate transport input, build an application command with actor/tenant/request/idempotency/version context, and serialize the result. They never issue SQL or implement invariants.

Collections use opaque cursor pagination with a hard limit, allowlisted filters/sorts and stable `(sort_key,id)` order. Mutations accept `Idempotency-Key`; PATCH/DELETE require an ETag/`If-Match` version where races matter. Errors are RFC 9457 Problem Details with stable `code` and `request_id`. Password/token input is write-only. Queue lists and certificate endpoints never expose message bodies or private/account keys.

The initial OpenAPI file defines representative tenant/domain/user/alias operations and shared security/errors. Remaining listed endpoints are added with Phase 2 implementation; undocumented routes are not claimed implemented.

Planned command surface: tenant/domain/user/alias CRUD; domain enable/disable, DNS-record generation and verification; user password, enable/disable/unlock, application-password and quota operations; mailbox list/show/update/delete; queue list/show/retry/cancel/pause/resume; certificate list/show/renew and ACME status; audit list. DELETE of users/domains returns an idempotent retention job rather than synchronously purging data. Domain DNS output includes MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT and client discovery records, each derived from the committed domain policy.

Alias kinds are user, domain, forwarding, distribution, catch-all, blackhole and reject. Creation performs bounded graph loop detection against a transactionally consistent alias version; delivery repeats visited/depth checks because the graph may change later.
