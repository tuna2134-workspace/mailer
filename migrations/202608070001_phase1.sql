CREATE TABLE tenants (
    id uuid PRIMARY KEY,
    name text NOT NULL CHECK (name <> ''),
    status text NOT NULL CHECK (status IN ('active','disabled','pending_deletion')),
    quota_bytes bigint NOT NULL DEFAULT 0 CHECK (quota_bytes >= 0),
    used_bytes bigint NOT NULL DEFAULT 0 CHECK (used_bytes >= 0 AND used_bytes <= quota_bytes),
    retention_days integer NOT NULL DEFAULT 30 CHECK (retention_days >= 0),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE domains (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    status text NOT NULL CHECK (status IN ('active','disabled','pending_deletion')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, name),
    UNIQUE (tenant_id, id)
);

CREATE TABLE users (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    local_part text NOT NULL CHECK (local_part <> ''),
    display_name text NOT NULL DEFAULT '',
    status text NOT NULL CHECK (status IN ('active','disabled','pending_deletion')),
    quota_bytes bigint NOT NULL CHECK (quota_bytes >= 0),
    used_bytes bigint NOT NULL DEFAULT 0 CHECK (used_bytes >= 0 AND used_bytes <= quota_bytes),
    failed_login_count integer NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
    locked_until timestamptz,
    last_login_at timestamptz,
    password_version bigint NOT NULL DEFAULT 1 CHECK (password_version > 0),
    password_changed_at timestamptz,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    deleted_at timestamptz,
    FOREIGN KEY (tenant_id, domain_id) REFERENCES domains(tenant_id, id),
    UNIQUE (tenant_id, domain_id, local_part),
    UNIQUE (tenant_id, id)
);

CREATE TABLE password_credentials (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE application_passwords (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    display_name text NOT NULL,
    secret_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz,
    revoked_at timestamptz,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id)
);

CREATE TABLE aliases (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    source text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('user','domain','forwarding','distribution','catch_all','blackhole','reject')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, source),
    UNIQUE (tenant_id, id)
);

CREATE TABLE alias_targets (
    alias_id uuid NOT NULL REFERENCES aliases(id) ON DELETE CASCADE,
    position integer NOT NULL CHECK (position >= 0),
    target text NOT NULL,
    PRIMARY KEY (alias_id, position)
);

CREATE TABLE mailboxes (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    name text NOT NULL,
    uid_validity bigint NOT NULL CHECK (uid_validity BETWEEN 1 AND 4294967295),
    uid_next bigint NOT NULL DEFAULT 1 CHECK (uid_next BETWEEN 1 AND 4294967295),
    highest_modseq bigint NOT NULL DEFAULT 1 CHECK (highest_modseq > 0),
    message_count bigint NOT NULL DEFAULT 0 CHECK (message_count >= 0),
    unseen_count bigint NOT NULL DEFAULT 0 CHECK (unseen_count >= 0 AND unseen_count <= message_count),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id),
    UNIQUE (tenant_id, user_id, name),
    UNIQUE (tenant_id, id)
);

CREATE TABLE messages (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    raw_message bytea NOT NULL,
    envelope_sender text NOT NULL,
    received_at timestamptz NOT NULL,
    rfc_message_id text,
    message_size bigint NOT NULL CHECK (message_size >= 0 AND message_size = octet_length(raw_message)),
    content_hash bytea NOT NULL,
    storage_state text NOT NULL CHECK (storage_state IN ('committed','deleting')),
    UNIQUE (tenant_id, id)
);

CREATE TABLE mailbox_messages (
    mailbox_id uuid NOT NULL REFERENCES mailboxes(id),
    message_id uuid NOT NULL REFERENCES messages(id),
    uid bigint NOT NULL CHECK (uid BETWEEN 1 AND 4294967295),
    modseq bigint NOT NULL CHECK (modseq > 0),
    flags text[] NOT NULL DEFAULT '{}',
    keywords text[] NOT NULL DEFAULT '{}',
    internal_date timestamptz NOT NULL,
    saved_date timestamptz,
    object_id uuid NOT NULL,
    expunged_at timestamptz,
    PRIMARY KEY (mailbox_id, message_id),
    UNIQUE (mailbox_id, uid)
);

CREATE TABLE queue_recipients (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    message_id uuid NOT NULL,
    recipient text NOT NULL,
    destination_domain text NOT NULL,
    state text NOT NULL CHECK (state IN ('pending','leased','deferred','delivered','failed','cancelled')),
    next_attempt_at timestamptz NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    lease_owner uuid,
    lease_token uuid,
    lease_expires_at timestamptz,
    enhanced_status_code text,
    failure_reason text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, message_id) REFERENCES messages(tenant_id, id),
    CHECK ((state = 'leased') = (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL))
);

CREATE INDEX queue_claim_idx ON queue_recipients (next_attempt_at, id)
    WHERE state IN ('pending','deferred','leased');

CREATE TABLE delivery_attempts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    queue_id uuid NOT NULL REFERENCES queue_recipients(id),
    attempted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    result text NOT NULL,
    enhanced_status_code text,
    diagnostic text
);

CREATE TABLE audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid REFERENCES tenants(id),
    actor_id uuid,
    request_id uuid NOT NULL,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id uuid,
    detail jsonb NOT NULL DEFAULT '{}',
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE ingestions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    spool_token uuid NOT NULL UNIQUE,
    state text NOT NULL CHECK (state IN ('receiving','sealed','committed','abandoned')),
    byte_count bigint NOT NULL DEFAULT 0 CHECK (byte_count >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL
);

CREATE TABLE api_tokens (
    id uuid PRIMARY KEY,
    tenant_id uuid REFERENCES tenants(id),
    display_name text NOT NULL,
    token_hash bytea NOT NULL,
    scopes text[] NOT NULL,
    allowed_source_networks cidr[] NOT NULL DEFAULT '{}',
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz,
    last_used_at timestamptz,
    revoked_at timestamptz,
    UNIQUE (token_hash)
);
