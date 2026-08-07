# Multitenancy

Shared-schema PostgreSQL is initial. Every owned aggregate carries tenant ID; unique keys and foreign keys include it where cross-tenant references would otherwise be possible. Authentication resolves a principal to allowed tenant/domain scopes. Request `tenant_id` is validated against that principal and cannot expand authority.

Application filtering is mandatory; PostgreSQL RLS is evaluated in Phase 1 as defense in depth after connection-pool transaction scoping is proven safe. No session tenant variable may leak across pooled connections. Quotas, rate limits, queue concurrency, DNS policies, signing keys and retention are tenant-scoped. System metrics avoid tenant/user labels unless bounded.

Contract/integration tests create two tenants and attempt ID substitution, alias targets, role escalation, pagination leakage, queue/certificate access and concurrent deletion across the boundary.

