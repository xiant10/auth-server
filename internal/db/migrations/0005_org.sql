-- Rollout step 8: org units and managers.

-- A department is a unit. The composite keys make a link across tenants
-- impossible, whatever the code above them does.
CREATE TABLE auth.org_units (
    id         text PRIMARY KEY,
    tenant_id  text NOT NULL REFERENCES auth.tenants (id),
    parent_id  text,
    name       text NOT NULL CHECK (name <> ''),
    kind       text NOT NULL DEFAULT 'department' CHECK (kind IN ('department', 'team')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, parent_id) REFERENCES auth.org_units (tenant_id, id)
);
CREATE INDEX org_units_parent ON auth.org_units (tenant_id, parent_id);

ALTER TABLE auth.memberships
    ADD COLUMN manager_id  text,
    ADD COLUMN org_unit_id text,
    ADD CONSTRAINT memberships_manager FOREIGN KEY (tenant_id, manager_id) REFERENCES auth.memberships (tenant_id, id),
    ADD CONSTRAINT memberships_unit FOREIGN KEY (tenant_id, org_unit_id) REFERENCES auth.org_units (tenant_id, id),
    ADD CONSTRAINT memberships_not_own_manager CHECK (manager_id <> id);
CREATE INDEX memberships_manager_id ON auth.memberships (tenant_id, manager_id);
CREATE INDEX memberships_org_unit_id ON auth.memberships (tenant_id, org_unit_id);
