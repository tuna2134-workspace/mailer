CREATE TABLE acme_cache_entries (
    kind text NOT NULL CHECK (kind IN ('certificate', 'account')),
    cache_key bytea NOT NULL,
    ciphertext bytea NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (kind, cache_key)
);

CREATE TABLE certificate_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_type text NOT NULL,
    directory_url text NOT NULL,
    domains text[] NOT NULL,
    detail text,
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX certificate_events_occurred_idx
    ON certificate_events (occurred_at DESC);

COMMENT ON TABLE acme_cache_entries IS
    'Encrypted ACME account and certificate blobs; encryption keys are never stored in PostgreSQL';
