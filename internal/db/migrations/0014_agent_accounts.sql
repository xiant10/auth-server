-- Tenant agent accounts: members of kind agent, such as an agent teammate.
-- An agent account has no sign-in, belongs to exactly one tenant, holds role
-- member, and is nobody's manager. The triggers hold that whatever the code
-- above them does. See docs/agent-identity.md, "Principals".
ALTER TABLE auth.users
    ADD COLUMN kind text NOT NULL DEFAULT 'person' CHECK (kind IN ('person', 'agent'));

-- Who gave an agent account's standing grant: the tenant's consent, recorded
-- with the admin whose live token created it. Empty for a person's own.
ALTER TABLE auth.agent_grants
    ADD COLUMN given_by text NOT NULL DEFAULT '';

CREATE FUNCTION auth.refuse_agent_sign_in() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM auth.users WHERE id = NEW.user_id AND kind = 'agent') THEN
        RAISE EXCEPTION 'an agent account has no sign-in' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER credentials_not_agent BEFORE INSERT OR UPDATE ON auth.credentials
    FOR EACH ROW EXECUTE FUNCTION auth.refuse_agent_sign_in();
CREATE TRIGGER user_identifiers_not_agent BEFORE INSERT OR UPDATE ON auth.user_identifiers
    FOR EACH ROW EXECUTE FUNCTION auth.refuse_agent_sign_in();

CREATE FUNCTION auth.check_agent_membership() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM auth.users WHERE id = NEW.user_id AND kind = 'agent') THEN
        IF NEW.role <> 'member' THEN
            RAISE EXCEPTION 'an agent account holds role member' USING ERRCODE = 'check_violation';
        END IF;
        IF EXISTS (SELECT 1 FROM auth.memberships WHERE user_id = NEW.user_id AND id <> NEW.id) THEN
            RAISE EXCEPTION 'an agent account belongs to one tenant' USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    IF NEW.manager_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM auth.memberships b JOIN auth.users u ON u.id = b.user_id
        WHERE b.tenant_id = NEW.tenant_id AND b.id = NEW.manager_id AND u.kind = 'agent'
    ) THEN
        RAISE EXCEPTION 'an agent account is nobody''s manager' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER memberships_agent BEFORE INSERT OR UPDATE ON auth.memberships
    FOR EACH ROW EXECUTE FUNCTION auth.check_agent_membership();

-- A unit's lead is who its members report to, so an agent account can't be one.
CREATE FUNCTION auth.check_unit_lead() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.lead_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM auth.memberships b JOIN auth.users u ON u.id = b.user_id
        WHERE b.tenant_id = NEW.tenant_id AND b.id = NEW.lead_id AND u.kind = 'agent'
    ) THEN
        RAISE EXCEPTION 'an agent account leads no unit' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER org_units_lead_not_agent BEFORE INSERT OR UPDATE ON auth.org_units
    FOR EACH ROW EXECUTE FUNCTION auth.check_unit_lead();
