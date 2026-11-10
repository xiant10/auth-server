-- A unit's lead, who the members placed in it report to unless an admin says
-- otherwise. It names a membership, like a manager link, so it can't cross
-- tenants, and it's kept when they leave so reinstating them restores it.
ALTER TABLE auth.org_units
    ADD COLUMN lead_id text,
    ADD CONSTRAINT org_units_lead FOREIGN KEY (tenant_id, lead_id) REFERENCES auth.memberships (tenant_id, id);
