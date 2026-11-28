---
title: "Configurable business roles in auth-server"
audience: contributor
kind: record
status: record
summary: "Tenant-defined business roles in auth-server, built from module permissions."
---

# Configurable business roles in auth-server

Record: the original proposal, kept for its reasoning and tests. Where business roles stand now is in [design.md](../design.md), "Business roles". Status when written: chosen direction. Phase 1 (auth foundation) built in auth-server 2026-11-05, uncommitted, and deployed to the local cluster with an empty catalog; phases 2 to 4 not started. Date: 2026-11-05. As built, the routes and the catalog format are in [`auth-server/docs/guides/service-api.md`](../guides/service-api.md), "Business roles". Property is designed against it from the start (`original-proposal.md` (in property's own project)), with no local role catalog. This changes the module boundary: modules keep scope, field and workflow rules, and auth-server holds which actions a person may take ([module contract](../../../contracts/module/README.md), "Access").

Based on the authorization review (`t10-property/docs/records/authorization-review.md`, in property's own project), [current membership schema](../../internal/db/migrations/0001_core.sql), [auth guards](../../internal/server/server.go), and [delegation verifier](../../verifier/verifier.go). No external library or policy engine is required for this proposed first version.

## Recommendation

Extend auth-server with tenant-defined business roles composed from module-defined permissions. Keep platform/tenant administration separate. Modules remain responsible for resource visibility, field masking, consent and workflow rules.

This is preferable to separate local role catalogs once property and knowledge need shared manager permissions, and fits future business modules. It is additional platform development, not something current auth-server already supports. The current `member/admin` membership enum and agent grant system cannot substitute for it.

The recommended division is:

| Owner | Responsibility |
|---|---|
| auth-server | Identity; membership; built-in administrative authority; tenant custom roles; role assignments; allowed module actions; audit and entitlement revisions. |
| Business module | Which records an action applies to; building/assignee/base scope; consent and masking; state transitions and approval constraints. |
| Agent verifier | Whether this delegated token and every grant permit the attempted action, in addition to current human rights. |
| Client | Show available features and explain access; never be the enforcement boundary. |

A role name has no security meaning: calling a custom role “Admin” must not confer tenant administration. Do not replace the existing admin enum with arbitrary strings or infer privileges from names.

## Suggested first version

Allow tenant admins to create, rename, clone, disable and assign roles, and choose permissions from a fixed catalog. A user can hold multiple business roles. Start with allow-only grants, no role inheritance, wildcards, executable rules, direct per-user permission overrides or explicit deny algebra. Absence of a grant means denied. Keep platform administration and tenant-admin promotion outside the custom catalog, preserving current last-admin protection and administrative guards.

Each module declares its permissions in its manifest (`GET /v1/module`, as `permissions`: key, description, catalog version, lifecycle), so the definitions live with the code that enforces them. auth-server registers them from reviewed deployment configuration, as it does runtimes in `clients.yaml`; a deploy check compares that configuration with each module's manifest, and auth-server never calls a module at runtime. Adding a module adds configuration, not auth-server code. Every key must start with the module's `action_prefix`. Tenant admins choose existing permissions; they cannot invent a permission string that bypasses server code. New catalog entries are never automatically added to existing roles. Retired/unknown entries confer no rights; show migration warnings rather than silently broadening a role.

Example catalog:

| Module | Example permissions |
|---|---|
| Property | `property:resident.read`, `property:resident.write`, `property:work_order.create`, `property:work_order.process`, `property:work_order.accept`, `property:work_order.transfer` |
| Collections | `property:collection.read`, `property:collection.contact`, `property:collection.manual_paid` |
| Finance | `property:bill.issue`, `property:settlement.post`, `property:settlement.reverse`, `property:adjustment.request`, `property:adjustment.approve`, `property:adjustment.execute` |
| Management | `property:notice.publish`, `property:task.assign`, `property:report.read`, `property:export`, `property:audit.read` |
| Knowledge | `knowledge:read`, `knowledge:entry.edit`, `knowledge:entry.publish`, `knowledge:qa.review` |

Use explicit permissions for material business actions, not one all-powerful `property:write`. A permission allows attempting a command; it cannot bypass the command's valid state, caller relationship, consent or exact-amount checks. Role customization does not turn P1's fixed business processes into configurable workflows.

Seed the PRD roles as templates. Operational roles can be cloned and edited, with deviations visible in an audit trail. Keep a versioned baseline for P1 acceptance; introducing customized assignments does not silently redefine the PRD's role matrix. System administrator maps to the existing tenant-admin authority, with explicit business capabilities defined by the module. Project manager receives property and knowledge permissions without account/security administration. Customer service does not inherit collection-contact permission by default.

## Scope must stay attached to the grant

Never return only the union of permissions and the union of all scopes. That would allow a user with customer-service project-wide read plus steward write in building A to write throughout the project.

Suggested model: each role assignment has a stable ID; module-owned scope bindings are keyed by that assignment ID. Auth returns granted actions with their assignment provenance. Each module evaluates the scopes of assignments granting the requested action and unions only those scopes. Missing scope binding means no resource access, never whole-project access.

For example:

```text
assignment 1: customer service → resident.read → property scope: project
assignment 2: steward → collection.contact → property scope: building A
assignment 3: knowledge reviewer → entry.publish → knowledge scope: property base
```

Auth owns these role assignments and action grants. Property owns building selection and assignment facts; knowledge owns base scope. Auth can carry opaque module scope references in responses if useful, but does not interpret room IDs or query property tables.

Role assignment and scope binding cross databases. Provision fail-closed: create the auth assignment first with no usable scope, then create its module bindings. On revocation, disable the auth assignment first; stale module bindings cannot restore access. Use idempotent administration commands and display incomplete setup explicitly. Deleting a role disables access even if cleanup has not run. Do not use an asynchronous mirrored “manager” boolean as the authority for knowledge publishing.

A module must also distinguish administrative setup rights from business write rights. A custom finance role cannot grant itself scope or assign other roles. Initially only tenant admins manage custom roles and bindings; delegated role administrators can be considered later with a separately defined grant ceiling.

## Proposed schema and APIs

Add tables without altering existing membership semantics:

- `permission_definitions`: module, permission key, description, catalog version, lifecycle; controlled by deployment/module registration.
- `tenant_roles`: tenant, role ID, display name, description, enabled, revision, optional template/version provenance.
- `role_permissions`: tenant-qualified role FK and known permission key.
- `member_role_assignments`: tenant-qualified membership/role FKs, assignment ID, active status, revision and audit actor/time.
- `tenant_authorization_revision`: incremented transactionally on entitlement changes; include change records in auth audit.

No cross-tenant assignment FKs, duplicate active assignment IDs or mutable permission namespaces. Modules store their scope bindings independently, retaining assignment IDs for audit.

Suggested new routes:

| API | Purpose |
|---|---|
| `GET /v1/tenants/{id}/permission-catalog` | Catalog visible to that tenant's admins, with the permissions its roles hold that confer nothing here. |
| `GET/POST /v1/tenants/{id}/roles` | List/create roles. |
| `GET/PATCH /v1/tenants/{id}/roles/{role}` | Inspect/edit/disable using expected revision. |
| `GET/POST /v1/tenants/{id}/members/{user}/role-assignments` | Inspect/assign business roles. |
| `DELETE /v1/tenants/{id}/members/{user}/role-assignments/{assignment}` | Revoke an assignment with concurrency protection. |
| `GET /v1/me/access` | Extended, not replaced: adds `modules`, the modules for which the caller holds any permission, and `module_admin`, the modules whose settings they may administer. Workbench builds navigation and Administration's module tabs from it; client hints only. |
| `GET /v1/me/permissions?module=property` | Current user's grants for one module with assignment provenance; client hints only. |
| Internal entitlement read | Registered service requests a tenant/user's active grants for its authorized module namespace, including membership/account/tenant status and revision. One user, or a batch of users for one request. |

The internal entitlement read is a module's single per-request check against auth: it returns account, tenant and membership status as well as grants, so a module adopting it drops its separate `people.Member()` call, and tenant suspension becomes visible to modules, which org reads don't provide today. Module admin is a catalog permission (`<prefix>:admin`), replacing the `tenant_admin` check on a module's admin routes when that module adopts this; tenant admins keep it implicitly.

These are proposed API shapes, not existing endpoints. Define the internal read's authentication and namespace allowlist explicitly; a service must not select arbitrary modules or mutate roles using client credentials. Return no unnecessary personal data. Changes require current tenant-admin authority and audit before/after values, in the shared record fields of [`contracts/audit/`](../../../contracts/audit/README.md), so Administration's Activity shows role changes beside membership changes. Revision conflicts return 409, preventing one admin from overwriting another's changes.

## Runtime authorization and revocation

A module command requires all of:

```text
valid token and current session/grant
AND active account + tenant + membership
AND current permission from an enabled role assignment
AND scope attached to that same assignment covers the record
AND field/consent/workflow rules
AND, for agents, action allowed by token and every delegation grant
```

Do not embed mutable custom permission lists in long-lived JWTs. Keep identity in tokens and resolve current entitlements server-side. Initial P1 should use uncached entitlement checks for protected requests and queued job dispatch/delivery, failing closed on auth failure. This adds latency and an availability dependency; measure it. A batch entitlement response for one request avoids one auth call per row. Modules still filter rows locally before pagination.

Revision numbers alone do not invalidate caches: a consumer must learn that a newer revision exists. Add cached reads later only with an explicit staleness contract or a validated revision mechanism. Immediate role revocation must not rely on a periodically refreshed cache. The existing delegated verifier's 60-second chain cache is a separate constraint; strict immediate grant revocation requires an uncached check or verifier change. Live user entitlement checks already stop business access after role removal, regardless of a still-valid grant.

For existing coarse agent actions such as `property:read`, retain an explicit mapping to permitted read-only tools during migration. The module still checks its precise human permission for each tool. Future fine-grained agent actions require coordinated changes to runtime allowlists and grants; do not silently reinterpret old grants as broader permissions. Keep `Identity.Allows` as the delegation ceiling and add a separate authorization resolver rather than changing its human behavior globally.

## Module lifecycle

A permission belongs to exactly one module; a role belongs to the tenant and may combine permissions from several modules, as a project manager holds `property:*` and `knowledge:*`. So the catalog follows what each environment deploys, and roles and assignments are never deleted because a module is missing.

**Definitions live in the module's repo.** Each module ships `permissions.yaml`: its permission keys, all under its `action_prefix`, with description, catalog version and lifecycle, plus its role templates (property's six PRD roles, for example). The manifest's `permissions` field serves the same content, and the module's tests keep the two equal.

**Each environment registers only what it deploys.** `clients.yaml` is baked into auth's image, but the set of modules differs per environment, so the catalog doesn't go there. Each module with business roles has a kustomize component in the workspace, `deploy/k8s/catalog/<id>/`, holding a copy of its `permissions.yaml` and merging it as key `<id>.yaml` into the `auth-server-permissions` ConfigMap. A component loads its own files, so this stays within kustomize's default load restrictions. An overlay lists the component beside the module's `MODULE_URLS` entry, and auth-server reads the mounted ConfigMap as a folder, `AUTH_PERMISSIONS_DIR`, one file per deployed module. `make check` compares each copy with the module's own file, and that every module in an overlay's `MODULE_URLS` with a `permissions.yaml` has its component listed, and the reverse. auth-server never calls a module to learn its permissions.

**Each module is held to its own namespace.**

- A catalog entry for module `property` may define only `property:*` keys; auth refuses to load anything else.
- Only service `t10-property` may read `property:*` through the internal entitlement read.
- A role may combine namespaces, and each grant is checked only by the module that owns it.

**Templates are offered, never pushed.** When a module is in the catalog, its templates appear on Workbench's Roles page as "Create from template". auth never adds roles to existing tenants by itself. A template's later version never changes a role a tenant already made; the page shows "template updated" with a diff for the admin to apply or ignore. A single-project install can create the template roles once with a bootstrap command.

**A module never deployed in an environment needs nothing.** Its permissions aren't in that environment's catalog, so the role editor never offers them and nothing can grant them.

**A module removed from an environment is marked unavailable, not deleted.** At startup auth compares the catalog in its database with the folder:

- A namespace with no file in the folder becomes `unavailable`. auth still starts.
- Unavailable permissions confer nothing, like retired and unknown ones, and the entitlement read returns nothing for that namespace.
- The role editor shows them greyed out as "module not deployed". A role left with no usable permission shows as inactive.
- Roles, their permission rows and their assignments, with their IDs, are kept. If the module comes back, its scope bindings still match the assignment IDs and access returns as it was. A mistaken overlay can't wipe a tenant's role setup.
- Removal is a separate, deliberate step: `authctl permissions-purge --module=<id> --confirm=<id>` is audited, refuses while the module is still in `AUTH_PERMISSIONS_DIR`, and removes that namespace's permissions from every role. It never deletes a role or an assignment. The module's own database, with its scope bindings, is the module's data, retired with it.

**A module deployed but not sold to a tenant** is not auth's concern. That switch lives in `t10-agent-control`, as the module contract proposes, and the module answers `enabled: false` in its manifest for that tenant. Workbench hides those permissions in that tenant's role editor, and the module refuses its requests regardless. auth doesn't call `t10-agent-control`.

**Retiring one permission** within a module follows its lifecycle: `active`, then `deprecated` (still works, shown with a migration warning, not offered for new roles), then `retired` (confers nothing). A new permission is never added to existing roles automatically.

**Agent actions stay in `clients.yaml`.** A module's coarse delegation actions, such as `property:read`, are listed on runtimes in the baked file. In an environment without the module they do nothing, because no server accepts its audience. A module's own runtime entry, such as `t10-property` for its AI requests, is marked `optional`, so auth starts where that module isn't deployed.

## Rollout recommendation

1. **Auth foundation:** catalog loaded per environment from `AUTH_PERMISSIONS_DIR`, with the namespace, unavailable and purge rules of "Module lifecycle", role/assignment storage, audit, tenant-admin APIs, internal entitlement read, the `/v1/me/access` additions, tests for isolation and revocation. Preserve existing consumers and built-in administration.
2. **Property adoption:** seed operational roles, implement assignment-bound scopes and action checks, and build a Roles page in Workbench. Keep building selection in property settings.
3. **Knowledge adoption:** check `knowledge:entry.*` with assignment-bound base scopes. Project managers can now publish approved reference content without becoming tenant admins.
4. **Other modules:** migrate deliberately. Do not remove old admin checks globally or grant every member new rights. Report unsupported modules clearly in the role editor.

This direction was chosen before property implementation, so auth is the sole business-role authority from the start; no local and central role catalogs are built side by side. Property's skeleton and registry work can start before phase 1; its role acceptance suite waits for it. This proposal does not claim it is implemented or alter existing service behavior.

Required tests: tenant isolation; unknown permission rejection; role names not conferring authority; role-edit concurrency; mixed-role scope isolation; immediate disable/demotion; knowledge base scoping; agent grant intersection; missing scope fail-closed; incomplete provisioning; auth outage; preservation of last-admin protection; old modules remaining compatible; a catalog entry outside its module's namespace refused; a service reading another module's namespace refused; a module dropped from the catalog leaving roles and assignments intact but conferring nothing, and restored unchanged on redeploy; purge removing only that namespace; and a template update never changing an existing role.
