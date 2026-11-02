The shared service should provide **identity, tenant/organization management, and platform administration**, with clear logical boundaries. For simplicity, implement it initially as a **modular monolith with one deployment and a unified admin UI**.

**1. Logical modules and ownership**

| Module | Responsibilities |
|---|---|
| **Identity / Auth** | Users, credentials, MFA, SSO, OAuth/OIDC clients, sessions, token issuance and validation metadata |
| **Tenant / Organization** | Tenants, memberships, departments, org hierarchy, manager relationships, tenant administrator assignments |
| **Platform Administration** | Platform administrator assignments, tenant lifecycle, platform settings, administrative permissions |
| **Agent Access** | Runtime identities, dynamic agent executions, delegation grants, expiration and revocation |
| **Audit** | Identity, membership, role, policy and grant changes; privileged administrative actions |

Business modules retain their own data and authorization rules:

- Deals owns deals, ownership, sharing, and deal visibility policies.
- Documents owns documents, folders, and document access policies.
- Shared organizational facts—such as “Bob manages Alice”—come from the shared service.

**2. Authentication requirements**

- Support first-party user login through OIDC authorization code flow with PKCE.
- Support a backend-managed browser session; keep access and refresh tokens server-side where using a BFF.
- Authenticate backend services and agent runtimes using confidential-client credentials or workload identity.
- Issue short-lived, audience-specific access tokens.
- Identify external users by **issuer + subject**, not email.
- Keep tokens small; do not embed org trees, resource lists, or detailed business permissions.
- Support session termination, credential rotation, and token/grant expiration.

**3. Tenant and organization requirements**

- A user can belong to multiple tenants with different roles.
- Maintain authoritative tenant memberships and their active/inactive status.
- Support departments, parent-child org units, and manager relationships.
- Keep reporting relationships distinct from resource ownership and permission inheritance.
- Enforce tenant boundaries and reject invalid cross-tenant relationships or hierarchy cycles.
- Validate membership when selecting an active tenant; a tenant ID supplied by a client is not authorization.
- Expose shared organizational data through stable APIs or internal module interfaces.

**4. Administrative authorization requirements**

| Role | Scope | Typical authority |
|---|---|---|
| Platform administrator | Platform | Create/suspend tenants, configure platform settings, assign tenant administrators |
| Tenant administrator | One tenant | Manage members, departments, and tenant configuration |
| Business-module administrator | Module within a tenant | Manage deal visibility or document policies |

Platform administrators need not belong to every tenant. **Platform administration must not automatically grant access to customer business records.** Any support access should be separately authorized, bounded, and audited.

Every backend endpoint must enforce permissions independently of the UI.

**5. Business authorization integration**

The shared service establishes identity and shared organizational facts. Each business module determines record-level access.

For example:

```text
Shared service:
  Bob is an active Acme member.
  Bob manages Alice.

Deals module:
  Alice owns Deal 123.
  Acme permits managers to read their employees’ deals.

Result:
  Bob may read Deal 123.
```

Business modules must:

- Apply current tenant membership and business policies.
- Filter authorized records before pagination, counts, aggregation, or export.
- Enforce distinct read, edit, delete, and export permissions.
- Support dynamic policy changes without requiring users to log in again.
- Centralize permission logic so all API and MCP entry points apply the same rules.

OpenFGA is optional. It can evaluate relationships, but it does not replace authentication or automatically filter database queries.

**6. Dynamic agent requirements**

- Register stable runtime/service identities; do not require a new OAuth client for every spawned agent.
- Assign each execution an agent/execution ID and a bounded grant.
- Bind grants to the authenticated runtime, user, tenant, allowed actions, resource constraints, and expiration.
- Derive identity from trusted credentials and server state, never from model-generated arguments.
- Enforce:

```text
Effective agent access =
    current user permissions
    ∩ execution grant
    ∩ applicable tenant and business policies
```

- Child-agent grants cannot exceed parent authority.
- Support revocation and define whether existing grants follow subsequent permission expansions.
- Use explicit delegated tokens when needed; ordinary OAuth does not automatically provide dynamic-agent identity.

Business-specific grant constraints should be interpreted by their owning module, keeping the identity module independent of business schemas.

**7. Unified administration UI**

Provide one UI for identity, tenant, platform, and agent administration. Business-policy screens may appear there while calling the owning business module’s API.

The UI must distinguish platform-wide actions from tenant-scoped actions and clearly show the active tenant.

**8. Deployment and consistency requirements**

Start with:

```text
One deployment
One unified admin UI
One database instance with separate module-owned schemas
Internal interfaces between modules
```

- Keep table ownership explicit; avoid uncontrolled cross-module writes.
- Use transactions for related changes where possible.
- Publish change events for separately deployed business modules.
- Define cache invalidation and revocation latency.
- Fail closed when required authorization information is unavailable.
- Audit administrative changes with actor, scope, target, timestamp, and outcome.

This structure supports a simple initial deployment while preserving the option to separate services later without redesigning ownership or authorization boundaries.