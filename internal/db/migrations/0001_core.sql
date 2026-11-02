-- Rollout step 1: accounts, tenants, memberships, sessions and audit.
-- Tables for later steps arrive in their own migrations.

CREATE TABLE auth.users (
    id           text PRIMARY KEY,
    status       text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    display_name text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE auth.user_identifiers (
    kind       text NOT NULL CHECK (kind IN ('username', 'phone', 'email')),
    value      text NOT NULL,
    user_id    text NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, value)
);
CREATE INDEX user_identifiers_user_id ON auth.user_identifiers (user_id);

CREATE TABLE auth.credentials (
    user_id             text PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
    password_hash       text NOT NULL,
    password_changed_at timestamptz NOT NULL DEFAULT now(),
    failed_count        integer NOT NULL DEFAULT 0,
    locked_until        timestamptz
);

-- The id has no underscore after its prefix, so the "__" in a namespaced room
-- name always marks where the tenant ends.
CREATE TABLE auth.tenants (
    id         text PRIMARY KEY CHECK (id ~ '^ten_[a-z0-9-]+$'),
    name       text NOT NULL,
    status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE auth.memberships (
    id         text PRIMARY KEY,
    tenant_id  text NOT NULL REFERENCES auth.tenants (id),
    user_id    text NOT NULL REFERENCES auth.users (id),
    role       text NOT NULL CHECK (role IN ('member', 'admin')),
    status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id),
    -- Target for the composite foreign keys that manager links add later.
    UNIQUE (tenant_id, id)
);
CREATE INDEX memberships_user_id ON auth.memberships (user_id);

CREATE TABLE auth.platform_admins (
    user_id    text PRIMARY KEY REFERENCES auth.users (id),
    granted_by text NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE auth.sessions (
    id                  text PRIMARY KEY,
    user_id             text NOT NULL REFERENCES auth.users (id),
    client_id           text NOT NULL,
    active_tenant_id    text REFERENCES auth.tenants (id),
    secret_hash         bytea,
    prev_secret_hash    bytea,
    idle_expires_at     timestamptz NOT NULL,
    absolute_expires_at timestamptz,
    revoked_at          timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_user_id ON auth.sessions (user_id);

CREATE TABLE auth.audit_log (
    id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at      timestamptz NOT NULL DEFAULT now(),
    actor   text NOT NULL,
    scope   text NOT NULL,
    action  text NOT NULL,
    target  text NOT NULL DEFAULT '',
    outcome text NOT NULL CHECK (outcome IN ('success', 'denied')),
    detail  jsonb NOT NULL DEFAULT '{}'
);

-- Migrations run as the app's role, which therefore owns this table and could
-- not be denied writes by GRANT alone. A trigger binds the owner too.
CREATE FUNCTION auth.audit_log_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$;

CREATE TRIGGER audit_log_no_rewrite
    BEFORE UPDATE OR DELETE ON auth.audit_log
    FOR EACH ROW EXECUTE FUNCTION auth.audit_log_append_only();

CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON auth.audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION auth.audit_log_append_only();
