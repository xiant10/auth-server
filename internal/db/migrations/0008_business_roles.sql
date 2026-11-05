-- Business roles: tenant-defined roles composed from the permissions deployed
-- modules declare. Membership's member/admin role is unchanged, and no role here
-- confers tenant or platform administration.

-- Every permission any deployment has declared. A module dropped from the
-- catalog keeps its rows, so tenants' roles keep referring to them; whether a
-- key confers anything is decided by the running catalog, not this table.
CREATE TABLE auth.permission_definitions (
    key         text PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]*:[a-z][a-z0-9_.]*$'),
    module      text NOT NULL,
    description text NOT NULL DEFAULT '',
    version     integer NOT NULL,
    lifecycle   text NOT NULL CHECK (lifecycle IN ('active', 'deprecated', 'retired')),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX permission_definitions_module ON auth.permission_definitions (module);

CREATE TABLE auth.tenant_roles (
    id               text PRIMARY KEY,
    tenant_id        text NOT NULL REFERENCES auth.tenants (id),
    name             text NOT NULL CHECK (name <> ''),
    description      text NOT NULL DEFAULT '',
    enabled          boolean NOT NULL DEFAULT true,
    revision         bigint NOT NULL DEFAULT 1,
    -- Where a role came from, so the editor can offer a newer template. Empty
    -- for a role built by hand.
    template_module  text NOT NULL DEFAULT '',
    template_id      text NOT NULL DEFAULT '',
    template_version integer NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX tenant_roles_name ON auth.tenant_roles (tenant_id, lower(name));

CREATE TABLE auth.role_permissions (
    tenant_id  text NOT NULL,
    role_id    text NOT NULL,
    permission text NOT NULL REFERENCES auth.permission_definitions (key),
    PRIMARY KEY (tenant_id, role_id, permission),
    FOREIGN KEY (tenant_id, role_id) REFERENCES auth.tenant_roles (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX role_permissions_permission ON auth.role_permissions (permission);

-- A module binds its own scope, such as buildings, to an assignment's ID, so an
-- ID is never reused: a revoked assignment stays, and assigning again makes a
-- new one.
CREATE TABLE auth.member_role_assignments (
    id            text PRIMARY KEY,
    tenant_id     text NOT NULL,
    membership_id text NOT NULL,
    role_id       text NOT NULL,
    status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    revision      bigint NOT NULL DEFAULT 1,
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    revoked_by    text NOT NULL DEFAULT '',
    revoked_at    timestamptz,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, membership_id) REFERENCES auth.memberships (tenant_id, id),
    FOREIGN KEY (tenant_id, role_id) REFERENCES auth.tenant_roles (tenant_id, id)
);
CREATE UNIQUE INDEX member_role_assignments_active
    ON auth.member_role_assignments (tenant_id, membership_id, role_id) WHERE status = 'active';
CREATE INDEX member_role_assignments_role ON auth.member_role_assignments (tenant_id, role_id) WHERE status = 'active';

-- Raised in the same transaction as any change to who may do what in a tenant,
-- and returned with every entitlement read.
ALTER TABLE auth.tenants ADD COLUMN authorization_revision bigint NOT NULL DEFAULT 0;
