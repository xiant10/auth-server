-- Rollout step 2: registration, MFA, recovery and the code flow.

ALTER TABLE auth.tenants ADD COLUMN require_mfa boolean NOT NULL DEFAULT false;

ALTER TABLE auth.sessions
    -- When this session last proved a second factor; carried into the client
    -- sessions it authorizes.
    ADD COLUMN mfa_at timestamptz,
    -- Spent refresh secrets, so a replay revokes the session rather than
    -- merely failing.
    ADD COLUMN retired_secret_hashes bytea[] NOT NULL DEFAULT '{}';

CREATE TABLE auth.mfa_factors (
    id               text PRIMARY KEY,
    user_id          text NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    kind             text NOT NULL CHECK (kind IN ('totp')),
    secret_encrypted bytea NOT NULL,
    last_used_step   bigint NOT NULL DEFAULT 0,
    verified_at      timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, kind)
);

CREATE TABLE auth.recovery_codes (
    user_id   text NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    code_hash bytea NOT NULL,
    used_at   timestamptz,
    PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE auth.reset_tokens (
    token_hash bytea PRIMARY KEY,
    user_id    text NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    issued_by  text NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);

CREATE TABLE auth.rate_limits (
    key          text NOT NULL,
    window_start timestamptz NOT NULL,
    count        integer NOT NULL,
    PRIMARY KEY (key, window_start)
);

CREATE TABLE auth.auth_codes (
    code_hash         bytea PRIMARY KEY,
    session_id        text NOT NULL REFERENCES auth.sessions (id),
    client_id         text NOT NULL,
    code_challenge    text NOT NULL,
    redirect_uri      text NOT NULL,
    expires_at        timestamptz NOT NULL,
    used_at           timestamptz,
    -- The client session this code produced, revoked if the code is replayed.
    issued_session_id text REFERENCES auth.sessions (id)
);

CREATE TABLE auth.invitations (
    token_hash  bytea PRIMARY KEY,
    tenant_id   text NOT NULL REFERENCES auth.tenants (id),
    role        text NOT NULL CHECK (role IN ('member', 'admin')),
    created_by  text NOT NULL,
    expires_at  timestamptz NOT NULL,
    accepted_at timestamptz
);
