-- Rollout step 5: service accounts and agent grants.

-- The name is what a service calls itself in an audience. Two hashes let a
-- secret rotate with no downtime.
CREATE TABLE auth.service_accounts (
    id               text PRIMARY KEY CHECK (id ~ '^svc_[a-z0-9-]+$'),
    name             text NOT NULL UNIQUE,
    secret_hash      bytea NOT NULL,
    next_secret_hash bytea,
    status           text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at       timestamptz NOT NULL DEFAULT now()
);

-- One row per execution, so the id is the execution id. The foreign keys keep a
-- whole chain on one user and tenant, whatever the code above them does.
CREATE TABLE auth.agent_grants (
    id          text PRIMARY KEY,
    parent_id   text,
    runtime_id  text NOT NULL REFERENCES auth.service_accounts (id),
    user_id     text NOT NULL,
    tenant_id   text NOT NULL,
    actions     text[] NOT NULL CHECK (cardinality(actions) > 0),
    audiences   text[] NOT NULL CHECK (cardinality(audiences) > 0),
    constraints jsonb NOT NULL DEFAULT '{}',
    depth       integer NOT NULL DEFAULT 1 CHECK (depth BETWEEN 1 AND 4),
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    UNIQUE (id, tenant_id, user_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES auth.memberships (tenant_id, user_id),
    FOREIGN KEY (parent_id, tenant_id, user_id) REFERENCES auth.agent_grants (id, tenant_id, user_id)
);
CREATE INDEX agent_grants_user_id ON auth.agent_grants (user_id);
CREATE INDEX agent_grants_tenant_id ON auth.agent_grants (tenant_id, created_at DESC);
CREATE INDEX agent_grants_parent_id ON auth.agent_grants (parent_id);
