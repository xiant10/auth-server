-- Rollout step 3: the mobile API, device keys and QR approval.

CREATE TABLE auth.devices (
    id                  text PRIMARY KEY,
    user_id             text NOT NULL REFERENCES auth.users (id),
    name                text NOT NULL,
    platform            text NOT NULL CHECK (platform IN ('ios', 'android')),
    -- Uncompressed P-256 points.
    approval_public_key bytea NOT NULL,
    session_public_key  bytea NOT NULL UNIQUE,
    -- True only if a second factor was proved when this device enrolled. A
    -- device enrolled by password alone proves nothing beyond that password,
    -- so it cannot satisfy an MFA policy.
    mfa_capable         boolean NOT NULL,
    last_used_at        timestamptz,
    revoked_at          timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX devices_user_id ON auth.devices (user_id);

ALTER TABLE auth.sessions ADD COLUMN device_id text REFERENCES auth.devices (id);
CREATE INDEX sessions_device_id ON auth.sessions (device_id) WHERE device_id IS NOT NULL;

CREATE TABLE auth.device_challenges (
    challenge_hash bytea PRIMARY KEY,
    purpose        text NOT NULL,
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz
);

-- A password was right and a TOTP code is still owed.
CREATE TABLE auth.mfa_challenges (
    token_hash bytea PRIMARY KEY,
    user_id    text NOT NULL REFERENCES auth.users (id),
    client_id  text NOT NULL,
    device     jsonb NOT NULL,
    tenant     text NOT NULL DEFAULT '',
    attempts   integer NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);

CREATE TABLE auth.qr_logins (
    id_hash        bytea PRIMARY KEY,
    -- The QR code shows the ID. Only the requester holds this, so someone who
    -- merely sees the code cannot collect the result.
    poll_hash      bytea NOT NULL UNIQUE,
    kind           text NOT NULL CHECK (kind IN ('login', 'device')),
    client_id      text NOT NULL,
    requester_ip   text NOT NULL,
    user_agent     text NOT NULL DEFAULT '',
    status         text NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending', 'claimed', 'approved', 'denied', 'consumed')),
    user_id        text REFERENCES auth.users (id),
    device_id      text REFERENCES auth.devices (id),
    -- The keys of a new device waiting on approval, for kind = 'device'.
    pending_device jsonb,
    expires_at     timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);
