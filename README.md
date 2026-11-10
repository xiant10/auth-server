# t10 Auth Server

The central identity, authentication, and JWT issuer service for the t10 multi-tenant AI platform.

## Project Description

**t10 Auth Server** is the identity backbone and single source of truth for accounts, tenant organizations, memberships, delegated agent grants, and WebRTC room admissions across the t10 ecosystem. All platform services verify caller identity and delegated permissions against tokens and public keys issued by this service.

### Key Capabilities

- **Multi-Tenant Identity & Organizations**: First-class support for multi-tenant accounts, organizational units (departments and teams), manager hierarchies, and invitations.
- **Cryptographic Token Issuance**: Issues ES256 JSON Web Tokens (JWT) and publishes a standard JWKS endpoint (`/.well-known/jwks.json`).
- **Delegated Agent Grants**: Issues scoped, principal-bound delegated tokens and standing grants for automated and interactive agent runs.
- **WebRTC Room Admission**: Generates signed LiveKit room admission tokens bound to tenant-namespaced rooms and user identities.
- **Multi-Language Authentication**: Built-in localized sign-in, registration, recovery, and account management pages in English and Simplified Chinese.
- **Administrative Access Control**: Granular separation between tenant administration (members, units, security) and platform administration (tenant lifecycle, user suspension, audit logs).

## Run locally

```sh
docker compose up --build
```

This starts Postgres, seeds `ada@acme.example` as a platform admin and admin of `ten_acme`, registers the runtimes in `clients.yaml` with dev secrets, and serves on `:8081`.

**The LiveKit secret must match.** Room tokens are signed with `LIVEKIT_API_SECRET`, which defaults to the example value. If `t10-livekit-agent/.env` sets a real one, put the same value in this repo's `.env`, or LiveKit answers every room token with 401.

Point the Mac client at it, with LiveKit running from `t10-livekit-agent`:

```sh
go run ./cmd/client -auth-url http://localhost:8081 -room voice-agent-demo
```

It opens a browser. Sign in as `ada@acme.example` with `change-me-enterprise-admin`, or register a new account there. Later runs reuse the session in the Keychain. Adding `-username` and `-password` still works, in dev mode only.

**The agent must join the namespaced room.** Admission puts the client in `ten_acme__voice-agent-demo`, so start the agent with `-room ten_acme__voice-agent-demo`. With its default room name, the two never meet.

To run `agent-pi` against it, with per-user calls and agent grants:

```sh
AUTH_KIND=jwt
JWT_ALGORITHMS=ES256
JWT_JWKS_URL=http://localhost:8081/.well-known/jwks.json
JWT_ISSUER=http://localhost:8081
JWT_AUDIENCE=t10,agent-pi
JWT_REQUIRED_SCOPES=agent:use
JWT_TENANT_CLAIM=tid
AUTH_URL=http://localhost:8081
AUTH_CLIENT_ID=agent-pi
AUTH_CLIENT_SECRET=dev-only-agent-pi-service-secret-change-me
```

In a container, use `http://host.docker.internal:8081` for `JWT_JWKS_URL` and `AUTH_URL`, but keep `JWT_ISSUER` as it is.

`t10-livekit-agent` with `LLM_PROVIDER=agent_pi` needs `AUTH_URL=http://localhost:8081`, `AUTH_CLIENT_ID=t10-livekit-agent` and `AUTH_CLIENT_SECRET=dev-only-t10-livekit-agent-secret-change-me`. `AGENT_PI_TOKEN` is gone.

## Deploy

Production runs on Kubernetes from `deploy/k8s/`, using the same image as Compose. See [docs/deployment.md](docs/deployment.md).

## Administration

This service has no admin screens. People administer t10 in two places, and both call the JSON routes below with the person's own token, so every check stays here:

| Who | Where | What |
| --- | --- | --- |
| Tenant admins | `workbench`, under Administration | Members, invitations, reset links, the org tree, each member's manager and unit, the MFA policy, running agents and the tenant's activity |
| Platform admins | The platform console, `t10-console`, on an internal address | Every tenant and user, tenant and user suspension, the platform role, name release and the platform audit log |

`/admin` sends a signed-in person to whichever they administer, from `AUTH_WORKBENCH_URL` and `AUTH_CONSOLE_URL`, and shows both links to someone who holds both roles. The account page links them too. The sign-in and account pages are in English and Simplified Chinese: they follow the browser's language until someone picks one with the switch, which a cookie remembers. New text needs an entry in `zhText` in `internal/server/i18n.go`, or a test fails.

## API

| Route | Access |
| --- | --- |
| `GET /healthz`, `GET /readyz`, `GET /.well-known/jwks.json` | Public |
| `POST /v1/token` (`authorization_code`, `refresh_token`, `client_credentials`, `agent_grant`; `password` in dev mode only), `POST /v1/revoke` | Public |
| `GET /v1/authorize`, `/v1/signin`, `/v1/register`, `/v1/recover`, `/v1/reset`, `POST /v1/signout` | Pages; writes need a same-origin request |
| `/v1/account`, `/v1/join` | Signed-in browser |
| `POST /v1/rooms/admission`, `GET /v1/me`, `GET /v1/me/access`, `POST /v1/logout` | Any user |
| `/v1/challenges`, `/v1/login/*` | Public; the mobile app's sign-in |
| `/v1/me/*`, `/v1/qr/{id}/*`, `POST /v1/devices/{id}/revoke` | Mobile app session |
| `/v1/grants`, `/v1/grants/{id}/*`, `/v1/org/*` | Service token. See [docs/service-api.md](docs/service-api.md) |
| `GET /admin`, `/admin/*` | Signed-in browser. Redirects to the console or workbench by role |
| `POST /v1/tenants`, `.../suspend`, `.../activate`, `POST /v1/tenants/{id}/members`, `POST /v1/identifiers/release` | Platform admin with a second factor proved in the last 15 minutes |
| `GET /v1/audit`, `GET /v1/tenants`, `GET /v1/runtimes`, `GET /v1/users`, `POST /v1/users/{user}/suspend`, `.../activate`, `PUT` and `DELETE /v1/users/{user}/platform-admin` | Platform admin with a second factor proved in the last 15 minutes |
| `GET` and `PATCH /v1/tenants/{id}`, `GET /v1/tenants/{id}/members`, `PATCH .../members/{user}`, `POST .../members/{user}/reset-link`, `POST .../invitations` | Tenant admin active in that tenant, or platform admin |
| `GET` and `POST /v1/tenants/{id}/units`, `PUT` and `DELETE .../units/{unit}`, `GET` and `PUT .../members/{user}/placement` | Tenant admin active in that tenant, or platform admin |
| `GET /v1/tenants/{id}/grants`, `POST .../grants/{grant}/revoke`, `GET .../audit` | Tenant admin active in that tenant, or platform admin |

`GET /v1/tenants/{id}/members` carries each member's name, account status, manager and unit. A manager is the one an admin set, who may have left, so saving a row back keeps the link. `PATCH /v1/tenants/{id}` with `require_mfa: true` answers `409 mfa_needed` unless the caller's own session has a second factor, because their next token would otherwise be refused.

**Org writes:** a unit body has `name`, `kind` (`department` or `team`) and an optional `parent_id`. A placement body has optional `manager_user_id` and `org_unit_id`. `PUT` replaces the whole value, so a field left out is cleared. Errors are `not_found`, `invalid_request`, `cycle` and `unit_in_use`.

**Suspending a user** blocks sign-in everywhere, ends their sessions and stops their agents. Reactivating lets them sign in again, but brings back neither. A platform admin must lose the role before being suspended, and the last platform admin can't lose it.

**Reset links:** a tenant admin can only reset a plain member whose account belongs to that tenant alone. Anyone else needs a platform admin, because a reset reaches every tenant the account holds.

**Recovery:** an account with TOTP resets with one recovery code plus a TOTP code, which keeps the factor, or two recovery codes, which remove it. An admin reset link keeps the factor, so an admin who issues one still cannot sign in as the user.

Routes and their access live in one table in `internal/server/server.go`. A route with no access panics at startup and fails a test.

## Operator commands

`authctl` reads `DATABASE_URL`, and takes passwords from `AUTHCTL_PASSWORD` or one line of stdin.

```sh
authctl gen-key
authctl gen-totp-key
authctl bootstrap --username root --tenant-id ten_acme --tenant-name Acme
authctl add-user --username grace --tenant-id ten_acme --role member
authctl service-add --name agent-pi
```

`bootstrap` only creates the first platform admin. Later ones are added from the Users page. `service-rotate`, `service-finish`, `service-disable` and `service-enable` manage a service's secret and status. `clients.yaml` lists what each runtime may request, and the server refuses to start if a listed runtime has no account.

## Sample accounts

For local testing, the running stack can add one account of each kind:

```sh
docker compose exec auth-server authctl samples-add
docker compose exec auth-server authctl samples-remove
```

They share the password `t10-sample-password`, so both commands refuse to run outside dev mode. [docs/test-users.md](docs/test-users.md) lists them, and explains how each kind of user is maintained.

## Test

Postgres-backed tests skip unless `TEST_DATABASE_URL` is set. They drop and rebuild the `auth` schema, so never point it at a real database.

```sh
docker run -d --rm --name auth-test-pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=auth_test -p 55432:5432 postgres:17-alpine
TEST_DATABASE_URL='postgres://postgres:test@localhost:55432/auth_test?sslmode=disable' go test -p 1 ./...
node --test verifier/ts/verifier.test.ts
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
