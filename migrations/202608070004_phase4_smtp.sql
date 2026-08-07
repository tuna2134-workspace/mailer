CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE FUNCTION mail_bytea_cat(state bytea, value bytea) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN state || value;

CREATE AGGREGATE mail_bytea_concat(bytea) (
    SFUNC = mail_bytea_cat,
    STYPE = bytea,
    INITCOND = ''
);

CREATE TABLE smtp_ingestions (
    id uuid PRIMARY KEY,
    state text NOT NULL CHECK (state IN ('receiving','committed','abandoned')),
    byte_count bigint NOT NULL DEFAULT 0 CHECK (byte_count >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '1 hour'
);

CREATE TABLE smtp_ingestion_chunks (
    ingestion_id uuid NOT NULL REFERENCES smtp_ingestions(id) ON DELETE CASCADE,
    position integer NOT NULL CHECK (position >= 0),
    content bytea NOT NULL CHECK (octet_length(content) <= 65536),
    PRIMARY KEY (ingestion_id, position)
);

CREATE INDEX smtp_ingestions_recovery_idx ON smtp_ingestions (expires_at)
    WHERE state = 'receiving';

ALTER TABLE messages ADD COLUMN IF NOT EXISTS envelope_recipients text[] NOT NULL DEFAULT '{}';

COMMENT ON TABLE smtp_ingestion_chunks IS
    'Bounded transient chunks; final authoritative message remains messages.raw_message BYTEA';
