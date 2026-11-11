# Service API

How a t10 runtime or microservice talks to the auth service. [design.md](design.md) explains why it works this way.

## Register a service

```sh
authctl service-add --name agent-pi      # prints the secret once
authctl service-rotate --name agent-pi   # adds a second secret, and both work
authctl service-finish --name agent-pi   # retires the old one
authctl service-disable --name agent-pi  # stops it, and every grant it holds
```

The name is what the service answers to in an audience. A service that creates grants also needs an entry under `runtimes` in `clients.yaml`, which limits what it may ask for. The server won't start if a listed runtime has no account.

## Tokens

Both requests go to `POST /v1/token`, as JSON or a form.

| `grant_type` | Also send | Returns |
| --- | --- | --- |
| `client_credentials` | `client_id`, `client_secret` | A 5-minute service token, with `aud=t10` and no user, tenant or scope |
| `agent_grant` | `client_id`, `client_secret`, `grant_id` | A delegated token of up to 5 minutes, plus `user_id`, `tenant_id` and `grant_id` |

A delegated token names the user in `sub` and `tid`, the runtime in `act.sub` and the grant in `grant`. Its `aud` lists the grant's services and never `t10`, and `scope` holds the grant's actions.

Only the grant's runtime, or a service listed in its audiences, can exchange it. Each exchange rechecks every grant in the chain, each runtime, the user and the membership.

| Error | Meaning | What to do |
| --- | --- | --- |
| 401 `invalid_client` | Wrong name or secret, or the service is disabled | Stop and alert |
| 400 `invalid_grant` | The grant is unknown, revoked, or the user lost access | Stop the run |
| 400 `grant_expired` | The grant ran out | Pause, and ask the user to send a request to renew it |

Replace a token when under 60 seconds remain, and retry with backoff if the auth service can't be reached.

## Grants

These routes take a service token as a bearer token.

| Route | Purpose |
| --- | --- |
| `POST /v1/grants` | Create a grant, a standing grant, or one firing of a standing grant |
| `GET /v1/grants/{id}/chain` | Read a live grant and its ancestors, root first. A stopped grant answers `invalid_grant` |
| `POST /v1/grants/{id}/extend` | Renew for a new user request, with `subject_token` set to that user's live token |
| `POST /v1/grants/{id}/revoke` | Stop it, along with everything beneath it |

`POST /v1/grants` takes `subject_token`, `actions`, `audiences`, and optionally `constraints` and `ttl_seconds`.

- **A user token as `subject_token`** starts a root grant for that user and tenant. Its trigger is `user`. A grant room admission creates has `voice`.
- **A delegated token** starts a child of its grant. A child can only narrow its parent and can't outlive it, and it keeps its parent's trigger and automation. The chain stops at 4 grants.
- **`standing: true` with a user token** records that person's consent to future runs. Only the `t10-automations` runtime may ask. It lasts 90 days, and each refresh of the person's session renews it to 90 days, writing at most once a day. It has no trigger and mints no token: exchanging it answers `invalid_grant`. Sign-out-everywhere, a password reset, suspension and membership removal end it, as they end any grant.
- **`standing: true` with `principal`** names a tenant agent account (`acc_…`) instead: the tenant's consent to runs as that account, such as an agent teammate's. The `subject_token` must be a tenant admin's live token, checked live, or it answers `403`. Only `t10-automations` may ask, and only for an active agent account of the token's tenant. The grant records the admin as `given_by`. It doesn't depend on anyone signing in again: it has no 90-day lapse, and ends when it's revoked, by any tenant admin, or when the account is suspended or removed, which every firing checks. The admin who gave it leaving doesn't end it.
- **`parent_id` with no `subject_token`** is one firing: a child of a standing grant, from the runtime that holds it. It must give `trigger`, one of `schedule`, `event` or `webhook`, and `automation`, its automation's ID of up to 64 letters, digits, `_` or `-`. It lasts 8 hours, as any grant, and mints tokens carrying `trg` and `automation`. Any other use of `parent_id`, or a `trigger` anywhere else, answers `invalid_request` or `invalid_grant`.
- **The user and tenant** come only from the token. Never pass values from model output into this request.

Actions and audiences must also be on the runtime's list in `clients.yaml`, which never allows a wildcard or the audience `t10`. A grant lasts 8 hours by default, and extending can't take it past 24 hours from creation.

A grant ID is safe to store, because it's useless without the runtime's secret. A session secret or user token is not.

## Token exchange

`ai-gateway-tools` trades a run's token, which is good only at the gateway, for one a module accepts: `POST /v1/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `client_id` and `client_secret`, `subject_token` and `audience`. The caller must be listed under `exchangers` in `clients.yaml` and named in the subject token's `aud`, and `audience` must be on the token's grant. The chain is checked as for any mint. The answer has the same `sub`, `tid`, `scope`, `act`, `grant`, `trg` and `automation`, an `aud` of that module alone, and ends no later than the subject token.

Where `AUTH_TOOL_GATEWAY=true`, a runtime with `tool_audience` in `clients.yaml` gets tokens whose only audience is that, when its grant lists it, plus its `model_audience`, `ai-gateway-llm`, when the grant lists that too, because model calls don't go through the tool gateway. A grant made before the runtime listed the gateway keeps its audiences until it ends, within 24 hours. Compose, Light and quickstart leave it off.

## Room admission

When `clients.yaml` marks a runtime `voice: true`, room admission creates a grant for that runtime and puts its ID in the participant's `t10.grant` attribute. The attribute sits inside the LiveKit-signed token, so a client can't change it. The agent reads it from the participant, and exchanges it. A rejoin gets a new grant, and a call can't extend past its 8 hours, because no user token reaches the agent.

## Verifying a token

Use `verifier/` in Go or `verifier/ts/verifier.ts` in TypeScript. Don't read `sub` yourself, because that would give an agent the user's full rights.

```go
v, _ := verifier.New(verifier.Config{Issuer: publicURL, URL: internalURL, Service: "crm-mcp", ClientSecret: secret})
who, err := v.Verify(ctx, bearer)
if err != nil { /* refuse */ }
if !who.Allows("crm:read") { /* refuse */ }
// Then apply who.UserID's own permissions, and every entry of who.Constraints().
```

| Token | Result |
| --- | --- |
| A person's, `aud=t10` | `UserID`, with no agent. `Allows` is always true, so your own permission check decides |
| A delegated one listing this service | `UserID` and `Agent`, with the live chain. `Allows` needs the action on the token and on every grant |
| A service's own, `aud=t10` | `ServiceID` and no user. `Allows` is always false |
| Anything else | Refused |

A delegated token is refused if its chain can't be fetched. Chains are cached for 60 seconds, so a revocation reaches a service within a minute, sooner than the 5 minutes a token lasts. Keys are cached and survive an auth outage, so tokens signed with a known key keep working until they expire.

## Org reads

These routes take a service token, and every one needs `tenant=<id>`.

| Route | Returns |
| --- | --- |
| `GET /v1/org/units` | The tenant's units, each with `members` (its own active members) and `lead_user_id` when it has a lead |
| `GET /v1/org/members` | One page of `members` in user ID order, with `next_cursor`, empty on the last page. Each has the fields below, including inactive and suspended members unless `status=active`. Takes `limit` (up to 500, default 100), `cursor`, `unit`, and `q`, which matches display names only |
| `GET /v1/org/units/{id}/members` | `user_ids` of active members, leaving out suspended accounts. Add `transitive=true` for the units beneath it |
| `GET /v1/org/members/{user}` | `user_id`, `role`, `status` (the membership), `user_status` (the account), `manager_user_id` (the nearest active manager), `assigned_manager_user_id` (the link as set, which can name someone who left), `org_unit_id`, `display_name` and `kind`, `person` or `agent` |
| `GET /v1/org/members/{user}/reports` | `user_ids` of active reports, leaving out suspended accounts, including those whose nearest active manager is this user. Add `transitive=true` for everyone beneath them |

**Agent accounts.** A member of `kind: agent` is a tenant agent account: it has no sign-in, holds role `member`, belongs to one tenant, and is nobody's manager or unit lead. Modules check its membership and roles as they check a person's. A tenant admin creates one with `POST /v1/tenants/{id}/agent-accounts` and `{display_name, manager_user_id?, org_unit_id?}`, renames it with `PATCH /v1/tenants/{id}/agent-accounts/{user}` and `{display_name}`, and removes it as any member, by setting its membership `inactive`, which revokes its grants.

Sign-in names never appear here, because they're unverified and can hold a phone number. Don't treat a member missing from a read as gone: act only on an explicit `status: inactive`.

An empty result is `[]`, so it's safe to pass straight to `WHERE owner_id = ANY(...)`. Cache for at most 60 seconds, and fail closed when both the cache and the service are unavailable.

## Business roles

Tenant admins build roles from the permissions that deployed modules declare, and assign them to members. A module checks them with the entitlement read below. None of this changes membership's `member` or `admin` role, and a role's name confers nothing. The design is [`proposals/auth-custom-roles.md`](../../proposals/auth-custom-roles.md) in the workspace.

**The catalog.** auth-server reads one `<module>.yaml` per deployed module from `AUTH_PERMISSIONS_DIR`, the overlay's catalog ConfigMap. Unset, no module has business roles. Each file holds the module's ID, its `prefix`, its catalog `version`, its `permissions` (each a `key` under the prefix, a `description` and a `lifecycle` of `active`, `deprecated` or `retired`) and its role `templates`. `service` names the only service that may read the module's entitlements, `t10-<module>` by default. auth-server refuses to start on a key outside the module's prefix, a file named for another module, or a template using a permission that isn't active.

```yaml
module: property
prefix: property
version: 1
permissions:
  - {key: property:resident.read, description: See residents in scope, lifecycle: active}
  - {key: property:admin, description: Property settings, lifecycle: active}
templates:
  - {id: steward, name: Steward, permissions: [property:resident.read]}
```

A module taken out of the catalog keeps its permissions in the database, and tenants' roles keep holding them, but they confer nothing until it comes back. `authctl permissions-purge --module=<id> --confirm=<id>` removes them from every role for good, and refuses while the module is still in `AUTH_PERMISSIONS_DIR`.

**The entitlement read.** `GET /v1/entitlements?tenant=<id>&module=<id>&user=<id>[&user=<id>...]`, with the module's service token, for up to 200 users. A service may read only the module its catalog entry names it for; any other answers `403`, and a module not deployed `404`. It is never cached, so read it on each protected request, and fail closed when it's unavailable.

| Field | Meaning |
| --- | --- |
| `tenant_status`, `revision` | The tenant's status, and its authorization revision, raised by every role, assignment and membership change |
| `users[].active` | The account, membership and tenant are all active. Otherwise `grants` is empty |
| `users[].account_status`, `membership_status` | Empty when there's no such account or membership |
| `users[].tenant_admin` | The built-in tenant admin role, which a module maps to its own administrator |
| `users[].grants[]` | `permission`, `assignment_id`, `role_id`. Bind your scope, such as buildings, to `assignment_id`, and union scope only across the assignments that grant the action asked |

One read returns account, membership and tenant status, so it replaces a separate `/v1/org/members/{user}` read for authorization.

**A module's own roles.** `GET /v1/module-roles?tenant=<id>&module=<id>`, with the module's service token, returns the enabled `roles` that grant something in that module, each with only that module's `permissions`, and the active `assignments` of them (`id`, `user_id`, `role_id`). So a module's own administrator can bind scope without tenant admin rights. It says nothing about a tenant's other roles, and any other service answers `403`.

**Tenant admin routes**, under `/v1/tenants/{id}`:

| Route | Does |
| --- | --- |
| `GET /permission-catalog` | The deployed modules with their permissions and templates, and `unavailable`: permissions this tenant's roles hold that confer nothing here, with `reason` `module_not_deployed` or `retired` |
| `GET`, `POST /roles` | List roles, or create one from `name`, `description` and `permissions`, or from `template: {module, id}`, whose name, description and permissions apply to fields left out |
| `GET`, `PATCH /roles/{role}` | Read a role, or change `name`, `description`, `enabled` or the whole `permissions` list. `revision` is required, and a stale one answers `409 stale_revision`. A permission the role already holds may stay after its module is gone; a new one must be active and deployed, or it answers `400 unknown_permission` |
| `GET`, `POST /members/{user}/role-assignments` | List a member's assignments, revoked ones included, or assign `role_id`. A disabled role answers `409 role_disabled` |
| `DELETE /members/{user}/role-assignments/{assignment}?revision=<n>` | Revoke. The ID is never reused: assigning again makes a new one |

A role reports `active` (enabled, with at least one permission that confers something here), `unavailable`, its `assignments` count, and `template` with `latest_version` when the module's catalog is newer than the role. A newer template never changes a role.

**For clients**, `GET /v1/me/access` adds `modules` and `module_admin`, and `GET /v1/me/permissions?module=<id>` returns the caller's own grants in their active tenant. Both are for showing what someone can do, never for enforcing it.

**Places and tenants.** `GET /v1/me/homes` lists where a signed-in person can go: their tenants with `workbench` addresses, each tenant's `apps`, the `console` for a platform admin, and their `account`. It's only for showing links. An app is a catalog module with an `app` block (`path` under the tenant, `label`, `label_zh`, `description`, `description_zh`), which links to `AUTH_APP_URLS` (`module=url`, comma separated) when the module has its own web app. It's listed for someone holding a role in that module in that tenant, and for that tenant's admins. A catalog entry may also have an `agent` block (`server`, `audience`, `actions`) declaring its agent tools; it grants nothing, and the workspace's `make check` holds `clients.yaml` and the deployment to it. `GET /` sends a browser to the one place someone has, or shows a chooser grouped by tenant when any of their tenants has an app. A client in `clients.yaml` may set `tenant: required`, so `/v1/authorize` asks someone with several tenants to pick, and honours a `tenant` parameter naming one of theirs, or `tenant: none`, so its sessions hold no tenant. See [`sign-in-and-landing.md`](sign-in-and-landing.md).

**Preferences.** `GET /v1/me/preferences` returns the caller's `language` (`en` or `zh-Hans`) and `theme` (`system`, `light` or `dark`), each left out until chosen. `PUT /v1/me/preferences` changes the fields it's given and keeps the others; an unknown value is `400`. Every web app reads them after sign-in and saves each change, so a choice in one app shows in all of them. `/v1/authorize` hands an app the saved language as `lang`. A language picked on a hosted page is saved at once when signed in, and when signed out, as on the sign-in page, it's saved by the sign-in that follows and wins over the saved one that once. With nothing saved, a language the app or page already had is saved.

**The account page** draws the frame every t10 app draws, from `t10-modkit/frame`: the Apps list from homes, the account menu (language, theme, Sign out) and the saved theme. `GET /v1/account?return_to=<address>` adds a link back to that address when it belongs to Workbench, the console or an `AUTH_APP_URLS` app, and keeps it in a cookie while the page's forms post back. Its Sessions panel lists the person's live browser sign-ins, each with the web apps open through it, and ends any other one (`action=signin_end`), with that browser's app sessions. `POST /v1/theme` saves a theme from the page. It is laid out as Workbench's settings page: one centred column of titled cards (Profile, Sign-in names, Security, Devices, Sessions), a row per setting with its action on the right, and each change opening in place. A sign-in name is removed from its own row, offered only while another remains.
