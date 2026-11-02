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
| `POST /v1/grants` | Create a grant |
| `GET /v1/grants/{id}/chain` | Read a live grant and its ancestors, root first. A stopped grant answers `invalid_grant` |
| `POST /v1/grants/{id}/extend` | Renew for a new user request, with `subject_token` set to that user's live token |
| `POST /v1/grants/{id}/revoke` | Stop it, along with everything beneath it |

`POST /v1/grants` takes `subject_token`, `actions`, `audiences`, and optionally `constraints` and `ttl_seconds`.

- **A user token as `subject_token`** starts a root grant for that user and tenant.
- **A delegated token** starts a child of its grant. A child can only narrow its parent and can't outlive it. The chain stops at 4 grants.
- **The user and tenant** come only from the token. Never pass values from model output into this request.

Actions and audiences must also be on the runtime's list in `clients.yaml`, which never allows a wildcard or the audience `t10`. A grant lasts 8 hours by default, and extending can't take it past 24 hours from creation.

A grant ID is safe to store, because it's useless without the runtime's secret. A session secret or user token is not.

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
| `GET /v1/org/units` | The tenant's units |
| `GET /v1/org/members` | One page of `members` in user ID order, with `next_cursor`, empty on the last page. Each has the fields below, including inactive and suspended members unless `status=active`. Takes `limit` (up to 500, default 100), `cursor`, `unit`, and `q`, which matches display names only |
| `GET /v1/org/units/{id}/members` | `user_ids` of active members, leaving out suspended accounts. Add `transitive=true` for the units beneath it |
| `GET /v1/org/members/{user}` | `user_id`, `role`, `status` (the membership), `user_status` (the account), `manager_user_id` (the nearest active manager), `assigned_manager_user_id` (the link as set, which can name someone who left), `org_unit_id` and `display_name` |
| `GET /v1/org/members/{user}/reports` | `user_ids` of active reports, leaving out suspended accounts, including those whose nearest active manager is this user. Add `transitive=true` for everyone beneath them |

Sign-in names never appear here, because they're unverified and can hold a phone number. Don't treat a member missing from a read as gone: act only on an explicit `status: inactive`.

An empty result is `[]`, so it's safe to pass straight to `WHERE owner_id = ANY(...)`. Cache for at most 60 seconds, and fail closed when both the cache and the service are unavailable.
