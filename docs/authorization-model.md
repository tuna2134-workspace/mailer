# Authorization model

Roles are bundles, not hard-coded bypasses: system administrator, tenant administrator, domain administrator, support operator, read-only auditor, automation service. Required scopes are `tenants:read/write`, `domains:read/write`, `users:read/write`, `aliases:read/write`, `mailboxes:read/write`, `queue:read/retry/delete`, `certificates:read/renew`, `audit:read`, `metrics:read`.

Authorization input is actor, credential ID/version, tenant, optional domain/resource, scope, action, source network and request ID. System-wide operations require an explicit system principal. Tenant/domain admins are constrained to owned resources. Support has no message-body or secret access. Body access is absent initially; adding it requires a dedicated scope, actor/reason/request audit, tenant policy, no-store responses and optional dual approval.

API and CLI call the same application command. Repository methods require tenant-scoped identifiers. Denials are audited without revealing whether another tenant's object exists.

