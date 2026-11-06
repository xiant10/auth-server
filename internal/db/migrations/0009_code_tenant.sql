-- The tenant a person picked on the hosted page, before any token exists. It's
-- empty when they didn't need to pick, and redeeming the code still checks it.
ALTER TABLE auth.auth_codes
    ADD COLUMN tenant_id text REFERENCES auth.tenants (id);
