-- The modules a person lets their assistant act in without asking, by action
-- prefix, in each tenant they belong to. A grant's chain carries <prefix>:apply
-- only while the chain's person has its prefix here (agents.Service.Chain).
CREATE TABLE auth.auto_apply (
    user_id    text NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    tenant_id  text NOT NULL REFERENCES auth.tenants (id) ON DELETE CASCADE,
    prefix     text NOT NULL CHECK (prefix ~ '^[a-z][a-z0-9_]{0,31}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, tenant_id, prefix)
);
