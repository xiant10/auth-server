---
title: "auth-server API"
audience: consumer
kind: reference
status: current
summary: "Every auth-server route: tokens, app and device sign-in, accounts, service reads, tenant and platform administration."
---

# auth-server API

The reference for every route `auth-server` serves: tokens, sign-in for apps and devices, the caller's own account, service reads, tenant administration and platform administration. Each route declares its access in one table in [`internal/server/server.go`](../internal/server/server.go), and a test fails if one has none.

The flows have their own guides, which this page doesn't repeat:

- [`service-api.md`](guides/service-api.md): service tokens, agent grants, token exchange, room admission, verifying a token, org reads and business roles.
- [`mobile-api.md`](guides/mobile-api.md): device keys, request signing, and which call comes when in the mobile app and the WeChat mini-program.
- [`sign-in-and-landing.md`](sign-in-and-landing.md): the hosted pages, the front door and the tenant picker.
- [`openapi.yaml`](openapi.yaml): the machine-readable spec of the mobile and `/v1/me` routes.

## Reaching it

| From | Base URL |
| --- | --- |
| A browser, or a client outside the cluster | The public auth URL, `http://localhost:8081` in Compose |
| Another service on the cluster | `http://auth-server:18000` |

The issuer in tokens is always the public URL, even when a service calls the internal one.

## Access

Every route has one of these.

| Access | Needs | When it's missing |
| --- | --- | --- |
| Public | Nothing | |
| Page | Nothing. A write must come from the auth server's own origin | `403 forbidden` |
| Browser | A signed-in browser session cookie, and same-origin writes | Redirect to `/v1/signin?next=…` |
| Service | A service token from `client_credentials` | `401 invalid_token` |
| User | A person's access token (`aud=t10`) | `401 invalid_token` |
| Device | A person's access token from a mobile device session | `403 forbidden` |
| Tenant admin | A user token active in the `{id}` tenant and an admin there, or a platform admin. A platform admin's use is written to that tenant's audit log | `403 forbidden` |
| Platform admin | A platform admin whose session proved a second factor in the last 15 minutes. Dev mode waives the factor | `403 forbidden` |

Every refusal by a user route is written to the audit log, in the tenant when the path names one.

## Conventions

- **JSON** both ways. `POST /v1/token` and `POST /v1/revoke` also take a form. Bodies are at most 64 KiB, and a request runs at most 20 seconds.
- **Errors** look like OAuth's: `{"error": "<code>", "error_description": "<words>"}`. See [Error codes](#error-codes).
- **IDs** carry a prefix: `usr_` people, `acc_` agent accounts, `ten_` tenants, `mem_` memberships, `ses_` sessions, `dev_` devices, `grt_` grants, `org_` org units, `rol_` roles, `rla_` role assignments, `svc_` service accounts, `jti_` token IDs. Treat the rest as opaque.
- **Tokens.** An access token lasts 5 minutes and names the person in `sub` and the tenant in `tid`. Replace one when under 60 seconds remain. [Token claims](#token-claims) lists every claim.
- **The tenant** comes from the token, never from a body, except where a route says so.

## Tokens and keys

| Method and path | Access | Does |
| --- | --- | --- |
| `GET /.well-known/jwks.json` | Public | The signing keys. Cache them; known keys keep working through an outage |
| `POST /v1/token` | Public | Every token grant, by `grant_type` (below) |
| `POST /v1/revoke` | Public | End a client's session from its refresh token. Answers `200` for a token it doesn't know, as RFC 7009 does |
| `POST /v1/logout` | User | End the caller's own session |

`POST /v1/token` by `grant_type`:

| `grant_type` | Also send | Returns |
| --- | --- | --- |
| `authorization_code` | `code`, `redirect_uri`, `code_verifier`, `client_id`, and `client_secret` for a confidential client. Optional `tenant` | `access_token` and `refresh_token` |
| `refresh_token` | `refresh_token`, `client_id`, `client_secret` when confidential. Optional `tenant`, to switch the session's tenant | New tokens; the refresh token rotates |
| `device_refresh` | `client_id`, `session_id`, `challenge`, `signature`, optional `tenant` | A device session's access token. See [`mobile-api.md`](guides/mobile-api.md#staying-signed-in) |
| `client_credentials` | `client_id`, `client_secret` | A service token |
| `agent_grant` | `client_id`, `client_secret`, `grant_id` | A delegated token for an agent run |
| `urn:ietf:params:oauth:grant-type:token-exchange` | `client_id`, `client_secret`, `subject_token`, `audience` | The same delegation, narrowed to one module |
| `password` | `username`, `password`, optional `tenant` | Dev mode only. Elsewhere it answers `unsupported_grant_type` |

```http
POST /v1/token
Content-Type: application/json

{"grant_type": "client_credentials", "client_id": "t10-collab", "client_secret": "…"}
```

```json
{"access_token": "eyJ…", "token_type": "Bearer", "expires_in": 300}
```

A person in several tenants who doesn't name one gets `400 invalid_request`, and a tenant they don't belong to `403 forbidden`. A tenant that requires a second factor answers `403 mfa_required` until they enrol one.

### Token claims

Every token is a JWT signed with ES256; check it against the keys at `/.well-known/jwks.json`, by `kid`. Each lasts 5 minutes. Every kind has `iss` (the public auth URL), `sub`, `aud`, `iat`, `exp` and `jti`.

| Kind | `sub` | `aud` | Also |
| --- | --- | --- | --- |
| A person's access token | The person, `usr_…` | `["t10"]` | `tid`, the active tenant (empty only for a platform admin with no tenant); `sid`, the session; `scope: "agent:use"` |
| A delegated token, for an agent run | The person or agent account the run acts for | The services the grant names, never `t10` | `tid`; `scope`, the run's actions; `act.sub`, the runtime's `svc_…`; `grant`, the grant ID; `trg`, why it runs (`user`, `voice`, `schedule`, `event`, `webhook` or `agent`); `automation`, when an automation started it |
| A service token | The service, `svc_…` | `["t10"]` | Nothing else: no tenant, session or scope, so no user route accepts it |

```json
{
  "iss": "http://localhost:8081",
  "sub": "usr_9a4f2b18c0e27189…",
  "aud": ["t10-collab"],
  "exp": 1793910000,
  "iat": 1793909700,
  "jti": "jti_4490cdb109af321e…",
  "tid": "ten_acme",
  "scope": "work:read",
  "act": {"sub": "svc_agent-pi"},
  "grant": "grt_98ac0145ba89fe21…",
  "trg": "user"
}
```

Don't authorize from `sub` yourself: a delegated token's rights are also bounded by its grant chain. Use the verifier, as [`service-api.md`](guides/service-api.md) shows.

## Browser sign-in

These serve HTML. Web apps send people to `/v1/authorize` and redeem the code at `/v1/token`.

| Method and path | Access | Does |
| --- | --- | --- |
| `GET /v1/authorize` | Page | Start an authorization-code flow with PKCE (`client_id`, `redirect_uri`, `state`, `code_challenge`, `code_challenge_method=S256`, optional `tenant`, `lang`) |
| `GET`, `POST /v1/signin` | Page | The sign-in page, and its form |
| `POST /v1/signin/qr`, `/v1/signin/qr/poll` | Page | Show a QR code for the mobile app to approve, and wait for it |
| `GET`, `POST /v1/register` | Page | Register. Outside dev mode only with an invitation, else `403 registration_closed` |
| `GET`, `POST /v1/recover`, `/v1/reset` | Page | Ask for a reset, and set a new password from a reset link |
| `GET`, `POST /v1/signout` | Page | The sign-out page, which signs the browser out of every web app |
| `GET /v1/signout/complete` | Page | The last step of signing out, from a one-time `ticket` |
| `POST /v1/me/browser-logout` | User | A ticket for that step: `{client_id, return_to}` |
| `POST /v1/language` | Page | Choose the signed-out pages' language in this browser. It saves nothing, and isn't offered with one language |
| `GET`, `POST /v1/account` | Browser | The account page: profile, language and theme (`action=language` with `lang`, `action=theme` with `theme`), sign-in names, security, devices and sessions |
| `GET`, `POST /v1/join` | Browser | Accept an invitation |
| `GET /` | Browser | The front door: one place to go, or a chooser |

The pages that set a password (register, recover, reset and the account page's password change) ask for it twice. The form sends the repeat as `password_again` or `new_password_again`. If the two differ, the page answers `400` and changes nothing, so the invitation, the reset link or the recovery code still works. The JSON routes below take it once: a client that sets a password asks for the repeat itself.
| `GET /admin`, `/admin/…` | Browser | Sends people to the console or Workbench |

## Mobile and mini-program sign-in

All Public. Each request is signed with the device's keys, as [`mobile-api.md`](guides/mobile-api.md) explains, and only client `t10-mobile` may use `/v1/login`.

| Method and path | Does |
| --- | --- |
| `POST /v1/challenges` | A one-time challenge for a `purpose`: `login`, `register`, `pair`, `refresh`, `approve` or `reauth` |
| `POST /v1/login` | Sign in: `{client_id, name, password, tenant?, device, challenge, signature}`. Answers `status: ok` or `mfa_required` |
| `POST /v1/login/mfa` | Finish with a TOTP code: `{mfa_token, code}` |
| `POST /v1/login/register` | Create an account with an invitation: `{client_id, name, display_name, password, invite, device, challenge, signature}` |
| `POST /v1/login/recover` | Reset a password with recovery codes: `{name, recovery_code, second_code?, code?, new_password}` |
| `POST /v1/login/pair`, `/v1/login/pair/poll` | Add a second device, approved from the first: `{client_id, device, challenge, signature}`, then `{poll_token, tenant?}` |
| `POST /v1/wechat/signin` | Mini-program sign-in: `{client_id, code, name, password, totp?, tenant?}` |
| `POST /v1/wechat/refresh`, `/v1/wechat/signout` | Refresh or end it: `{client_id, session_id, code, tenant?}` |

## The caller's own account

| Method and path | Access | Does |
| --- | --- | --- |
| `GET /v1/me` | User | The person: `user_id`, `display_name`, `active_tenant`, `tenants`, `names`, `totp_enabled`, `recovery_codes_left` and `devices` |
| `PATCH /v1/me` | User | Change `display_name` |
| `GET /v1/me/access` | User | What this token can do: `tenant_admin`, `platform_admin`, `platform_verified`, `tenant_verified`, `modules`, `module_admin`, `managed_agents`. For showing, not enforcing |
| `GET /v1/me/permissions?module=<id>` | User | The caller's business-role grants in that module, in their active tenant |
| `GET /v1/me/homes` | User | Where they can go: tenants with Workbench links and apps, the console, the account page |
| `GET`, `PUT /v1/me/auto-apply` | User | `{modules}`: the modules, by action prefix such as `work`, whose propose actions the person lets their assistant apply without asking, in the token's tenant. Empty by default. `PUT` replaces the list and is audited (`auto_apply.set`). An agent's token has no session, so it can never change this |
| `GET`, `PUT /v1/me/preferences` | User | `language`, `theme` and `greeting`, and the `languages` the deployment offers (`AUTH_LANGUAGES`). `PUT` changes only the fields given, and refuses a language not offered |
| `GET /v1/me/session` | User | `{"status": "ok"}` while the session behind the token is alive, else `401` |
| `POST /v1/rooms/admission` | User | Join a call: `{room, tenant?, client?}`, answering `room_token`, `room_name`, `identity`, `assertion`, `server_url`, `expires_at`, `can_publish`. See [`service-api.md`](guides/service-api.md#room-admission) |

Device routes change the account from the mobile app. Each needs a `challenge` and a `signature` made with the approval key for its action ([`mobile-api.md`](guides/mobile-api.md#signing)).

| Method and path | Body, beside the signature |
| --- | --- |
| `POST /v1/me/password` | `new_password` |
| `POST /v1/me/names`, `/v1/me/names/remove` | `name` |
| `POST /v1/me/totp/start`, `/confirm`, `/disable` | `code` to confirm |
| `POST /v1/me/recovery-codes` | Returns new codes, replacing the old ones |
| `POST /v1/me/signout-all` | Ends every session and grant |
| `POST /v1/me/invitations/accept` | `invite` |
| `POST /v1/devices/{id}/revoke` | Removes a device |
| `POST /v1/qr/{id}/claim`, `/approve`, `/deny` | Approve or deny a browser's QR sign-in |

## Service reads and grants

Service routes take a service token. [`service-api.md`](guides/service-api.md) explains each one.

| Method and path | Does |
| --- | --- |
| `POST /v1/grants` | Create a grant, a standing grant, or one firing of a standing grant |
| `GET /v1/grants/{id}/chain` | A live grant and its ancestors, root first. Each link holds a `<prefix>:apply` only while the chain's principal is a person whose auto-apply choice lists `<prefix>`; a tenant agent account's never does. The grants keep what was asked for, so a change of choice reaches live grants |
| `POST /v1/grants/{id}/extend` | Renew it for a person's new request: `{subject_token}` |
| `POST /v1/grants/{id}/revoke` | Stop it and everything under it |
| `GET /v1/org/units?tenant=` | Units with their members and leads |
| `GET /v1/org/units/{id}/members?tenant=` | `user_ids`, with `transitive=true` for units beneath |
| `GET /v1/org/members?tenant=` | A page of members: `limit` (to 500), `cursor`, `unit`, `q`, `status=active` |
| `GET /v1/org/members/{id}?tenant=` | One member, with manager, unit and `kind` (`person` or `agent`) |
| `GET /v1/org/members/{id}/reports?tenant=` | `user_ids` of reports, with `transitive=true` for everyone beneath |
| `GET /v1/users/{id}/preferences` | A person's preferences, such as the call `greeting` |
| `GET /v1/entitlements?tenant=&module=&user=…` | Business-role grants in a module, for up to 200 users. Only the module's own service |
| `GET /v1/module-roles?tenant=&module=` | The module's roles and their assignments |

## Tenant administration

Tenant admin routes, under `/v1/tenants/{id}`.

| Method and path | Does |
| --- | --- |
| `GET`, `PATCH /v1/tenants/{id}` | Read the tenant, or set `require_mfa`. Turning it on needs the caller to have signed in with a second factor (`409 mfa_needed`) |
| `GET /members` | Members with names, roles, status, manager and unit |
| `PATCH /members/{user}` | Change `role` (`member` or `admin`) or `status` (`active` or `inactive`). The last admin can't go (`409 last_admin`) |
| `POST /members/{user}/reset-link` | A one-time password reset link to hand over |
| `POST /invitations` | An invitation for `role`, answering its link |
| `GET`, `POST /units` | List units, or create one: `{name, kind, parent_id?}` |
| `PUT /units/{unit}` | Change `name`, `kind`, `parent_id`, `lead_user_id`. A loop answers `409 cycle` |
| `DELETE /units/{unit}?move=up` | Remove a unit. With members and no `move=up`, it answers `409 unit_in_use` |
| `GET`, `PUT /members/{user}/placement` | A member's `manager_user_id` and `org_unit_id` |
| `PUT /placements` | Place several at once: `{placements: [{user_id, manager_user_id, org_unit_id}]}` |
| `POST /agent-accounts` | Create an agent account: `{display_name, manager_user_id?, org_unit_id?}` |
| `PATCH /agent-accounts/{user}` | Rename it: `{display_name}` |
| `GET /grants?after=` | Agent grants, running ones first, with `valid` and a `next` cursor |
| `POST /grants/{grant}/revoke` | Stop a grant in this tenant |
| `GET /audit` | The tenant's newest audit `records`: `at`, `actor`, `action`, `target`, `outcome`, and when known `name` (the actor's sign-in name) and `ip` (the address the request came from) |
| `GET /permission-catalog` | Deployed modules' permissions and templates |
| `GET`, `POST /roles`; `GET`, `PATCH /roles/{role}` | Business roles. A change needs the `revision` read (`409 stale_revision`) |
| `GET`, `POST /members/{user}/role-assignments` | A member's role assignments, or assign `role_id` |
| `DELETE /members/{user}/role-assignments/{assignment}?revision=` | Revoke one |

## Platform administration

Platform admin routes, used by `t10-console`.

| Method and path | Does |
| --- | --- |
| `GET /v1/tenants?q=` | Tenants |
| `POST /v1/tenants` | Create one: `{id, name}` |
| `POST /v1/tenants/{id}/suspend`, `/activate` | Suspend or reopen a tenant |
| `POST /v1/tenants/{id}/members` | Add a person: `{user_id, role}` |
| `GET /v1/users?q=` | People |
| `POST /v1/users/{user}/suspend`, `/activate` | Suspend or reopen an account |
| `PUT`, `DELETE /v1/users/{user}/platform-admin` | Make or unmake a platform admin. The last can't go (`409 last_platform_admin`) |
| `POST /v1/identifiers/release` | Free a sign-in name: `{name}` |
| `GET /v1/runtimes` | Runtimes registered in `clients.yaml` |
| `GET /v1/audit` | The platform's newest audit records |

## Health

`GET /healthz` answers `{"status": "ok"}` while the process runs, and `GET /readyz` answers `{"status": "ready"}` while it can reach Postgres, else `503 unavailable`.

## Error codes

| Status | `error` | Means |
| --- | --- | --- |
| 400 | `invalid_request` | A malformed or invalid body or parameter |
| 400 | `invalid_grant` | Wrong sign-in, or a code, refresh token or grant that is invalid, revoked or expired |
| 400 | `grant_expired` | An agent grant ran out; ask the person to renew it |
| 400 | `unsupported_grant_type` | A `grant_type` this server doesn't take |
| 400 | `unknown_permission` | A role names a permission that isn't active and deployed |
| 401 | `invalid_token` | A missing, invalid or expired bearer token |
| 401 | `invalid_client` | Wrong client or service secret, or a disabled service |
| 403 | `forbidden` | Not permitted, or a cross-origin write |
| 403 | `mfa_required` | The tenant requires a second factor |
| 403 | `registration_closed` | Registration needs an invitation |
| 404 | `not_found`, `unknown_module` | No such record, or a module that isn't deployed |
| 409 | `conflict`, `stale_revision`, `role_disabled`, `cycle`, `unit_in_use`, `last_admin`, `last_platform_admin`, `platform_admin`, `user_suspended`, `mfa_needed` | The change conflicts with the current state, as named |
| 429 | `rate_limited` | Too many attempts |
| 503 | `unavailable` | A dependency is down |
| 500 | `server_error` | Logged with the route; retry later |

The mobile routes add their own codes, such as `device_approval_required` and `device_revoked`, listed in [`mobile-api.md`](guides/mobile-api.md).

## Docs for coding agents

`POST /docs/mcp` serves this repo's docs for people building on t10, over MCP and with no token, as the workspace's [docs contract](../../contracts/docs/README.md) describes. `auth-server docs <addr>` serves only that route, for the contract's suite.
