# Agent identity

How agents, their runs and the things that start them get identity from `auth-server`. [`design.md`](design.md) explains grants, and [`service-api.md`](service-api.md) is their reference. This document adds what the agent plane needs on top.

Status: proposed, nothing built. Tenant agent accounts and 90-day standing grants are agreed. Today every root grant needs a live user token, lasts at most 24 hours from creation, and a `client_credentials` token has no tenant, so no run can start without a person present. That's the gap this closes.

## Pools and runtimes

The `auth-server` boundary doesn't change. `t10-agent-control` and `t10-automations` issue nothing.

- **Each pool's harness is a runtime.** Add it to `clients.yaml` with its own account, audience, actions and audiences. A runtime is per harness and bundle owner, not per conversation, as the auth requirements ask.
- **A pool's runtime needs the tools its agent uses.** Step 6 of "Adding a module" in [`contracts/module/README.md`](../../contracts/module/README.md) applies: list new tool audiences on each harness and on `t10-livekit-agent`, or tools disappear on calls.
- **Narrow voice tokens.** Today's token names every agent's audience. Have the voice worker ask for one target audience per exchange, the session's pool's, using `audience` narrowing at `POST /v1/token`, which `auth-server` would need to add. Do this before adding a third audience.
- **Pool audience.** Use one audience per harness service, `agent-pi`, `agent-sales`, `agent-codex`. `JWT_AUDIENCE` already works this way. A new audience means editing `clients.yaml` and deploying `auth-server`, so adding a pool is a deploy, even when routing to it isn't.
- **Agent access is a route.** `agent:use` stays a coarse right. Which agents a tenant may use is `agent_tenant`, enforced at placement. A harness rejects an `Agent-Name` it doesn't serve.

## Runs

A **run** is one execution of an agent under one grant. The grant ID is already the execution ID. Two facts about every run become explicit, and puts both on its grant so every service downstream can read them from the token, without trusting a header.

| Fact | Values | Read by |
| --- | --- | --- |
| **Principal**: whose rights the run uses | A person (`usr_…`), or a tenant agent account (`acc_…`) | Every module, as today: `sub` and `tid` |
| **Trigger**: why it's running | `user`, `voice`, `schedule`, `event`, `webhook`, `agent` | Tool gateway, model gateway, evidence. A new `trg` claim, with `automation` when one started it |

```text
grant(id, runtime, principal, tenant, actions, audiences, constraints,
      trigger, automation?, parent?, expires_at)
```

Tools and modules keep reading `sub` and `tid`, so nothing in `t10-collab` changes for a person's runs.

### Principals

**A person.** As today. A run a person starts interactively has trigger `user` or `voice`. A run started later on their behalf has trigger `schedule`, `event` or `webhook`, and descends from a standing grant the person created while signed in.

**A tenant agent account.** A tenant admin creates one in `workbench`, such as "Lead triage". It's a membership of kind `agent` in `auth-server`, with role `member` and no sign-in. Modules apply its permissions exactly as they apply a person's, because they look up a membership either way, so a module needs no change to serve it. It's for work that belongs to the organisation rather than to a person: triaging a new lead, a nightly clean-up. It never holds a token. Only grants rooted in it do.

A tenant agent account isn't a platform service account, and gives no path into other tenants. It also isn't a way to skip consent: creating an automation that runs as one needs a tenant admin's live token, and the grant chain records that admin.

### Standing grants

A standing grant is a person's consent to future runs, recorded in `auth-server`:

| Property | Value |
| --- | --- |
| Created by | `POST /v1/grants` with `standing: true`, a **live user token**, and the runtime `t10-automations` |
| Lasts | 90 days by default, renewed whenever the person uses t10, and revoked by sign-out-everywhere, suspension or membership removal, as grants are |
| Holds | Actions and audiences, which must be within the runtime's list. Delete and export stay out, as they do for every unattended grant today |
| Used by | `t10-automations` only, to create an ordinary 8-hour child grant per firing. Only the child's runtime can mint tokens |
| Never | Mints a token itself, or extends past its own expiry |

The voice path already works this way: room admission creates a grant, and the voice worker's grant becomes the parent of `agent-pi`'s. A firing is the same chain with `t10-automations` in the voice worker's place.

### Session ownership

A session stays owned by `(tenant, principal)`. For a person's automation that's the person, so its conversations appear in their own sidebar, marked with their trigger. For an agent account, nobody can open the session directly. Its output reaches people in one of two ways:

- **Delivery.** The automation posts a notification, or a module record, through tools the account may use.
- **Takeover.** A person with access to the automation presses Continue, and a handoff copies the conversation into a new session they own. Handoff's existing rule applies: the export call carries the session owner's authority, which here is a child grant from the account's standing grant, made by `t10-automations` for that one export.

## Changes to `auth-server`

| Change | For |
| --- | --- |
| `trigger` and `automation` on grants, as `trg` and `automation` claims on delegated tokens | `ai-gateway-tools`, `ai-gateway-llm` and evidence read why a run is running |
| `standing: true` on `POST /v1/grants`, for the `t10-automations` runtime only, 90 days, renewed by use | A person's consent to future runs |
| Memberships of kind `agent`, created by a tenant admin, with no sign-in | Organisation-owned runs |
| A runtime entry for `t10-automations` in `clients.yaml`, and its account created by `auth-setup` only when `T10_AUTOMATIONS_SECRET` is set, as `T10_COLLAB_SECRET` is | Firing automations, with no new secret in a stack that doesn't run it |
| `ai-gateway` added to each harness runtime's audiences, where a gateway runs | Harnesses send the run's delegated token on model and tool calls. Light's `clients.yaml` doesn't list it |
| `audience` narrowing at `POST /v1/token` | One target audience per voice exchange |
| `tenant_verified` at `GET /v1/me/access`, then `policy_admin` and `compliance_viewer` | Tenant admins step up within 15 minutes, as platform admins do, and governance roles |

## Open questions

- **Should tenants shorten consent?** 90 days, renewed by use, is the default. Some tenants will want automations to stop when their creator hasn't signed in for a month, which would be a tenant setting.
- **Who can see an agent account's conversations?** Takeover by handoff covers continuing one. Reading without taking over needs a share rule, which no harness has.
- **What about sessions nobody reopens when a pool retires?** Exporting them needs a service path with no user token. A tenant agent account doesn't solve it, because those sessions belong to people. The same work covers volume backups.
