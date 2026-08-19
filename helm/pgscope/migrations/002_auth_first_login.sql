CREATE TABLE IF NOT EXISTS pgscope_users (
    id bigserial PRIMARY KEY,
    username text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    role text NOT NULL DEFAULT 'viewer',
    must_change_password boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pgscope_sessions (
    id bigserial PRIMARY KEY,
    token_hash text NOT NULL UNIQUE,
    user_id bigint NOT NULL
        REFERENCES pgscope_users(id)
        ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pgscope_sessions_user_id
ON pgscope_sessions(user_id);

CREATE INDEX IF NOT EXISTS idx_pgscope_sessions_expires_at
ON pgscope_sessions(expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE
ON pgscope_users
TO pgscope_api;

GRANT SELECT, INSERT, UPDATE, DELETE
ON pgscope_sessions
TO pgscope_api;

GRANT USAGE, SELECT
ON ALL SEQUENCES IN SCHEMA public
TO pgscope_api;
