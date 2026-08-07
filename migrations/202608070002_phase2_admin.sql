CREATE TABLE roles (
    name text PRIMARY KEY,
    scopes text[] NOT NULL,
    CHECK (cardinality(scopes) > 0)
);

INSERT INTO roles (name, scopes) VALUES
('system_administrator', ARRAY['tenants:read','tenants:write','domains:read','domains:write','users:read','users:write','aliases:read','aliases:write','mailboxes:read','mailboxes:write','queue:read','queue:retry','queue:delete','certificates:read','certificates:renew','audit:read','metrics:read']),
('tenant_administrator', ARRAY['domains:read','domains:write','users:read','users:write','aliases:read','aliases:write','mailboxes:read','mailboxes:write','queue:read']),
('domain_administrator', ARRAY['domains:read','users:read','users:write','aliases:read','aliases:write','mailboxes:read']),
('support_operator', ARRAY['domains:read','users:read','mailboxes:read','queue:read']),
('read_only_auditor', ARRAY['tenants:read','domains:read','users:read','aliases:read','mailboxes:read','queue:read','certificates:read','audit:read','metrics:read']),
('automation_service', ARRAY['domains:read','users:read','users:write','aliases:read','aliases:write','queue:read','queue:retry']);

CREATE TABLE role_bindings (
    id uuid PRIMARY KEY,
    tenant_id uuid REFERENCES tenants(id),
    domain_id uuid,
    principal_id uuid NOT NULL,
    role_name text NOT NULL REFERENCES roles(name),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid NOT NULL,
    FOREIGN KEY (tenant_id, domain_id) REFERENCES domains(tenant_id, id)
);

CREATE TABLE idempotency_keys (
    tenant_id uuid,
    key text NOT NULL CHECK (length(key) BETWEEN 16 AND 200),
    operation text NOT NULL,
    request_hash bytea NOT NULL,
    response_status integer,
    response_body jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, key, operation)
);

CREATE INDEX audit_events_tenant_time_idx ON audit_events (tenant_id, occurred_at DESC, id DESC);
CREATE INDEX api_tokens_active_idx ON api_tokens (id) WHERE revoked_at IS NULL;
