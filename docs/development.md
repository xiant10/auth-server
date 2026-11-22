---
title: "auth-server development"
audience: contributor
kind: reference
status: current
summary: "auth-server internals: code layout, configuration, data model, sign-in and grant flows, authctl, tests and troubleshooting."
---

# Development

How auth-server is built inside, for changing it. Every route and its access is in [api.md](api.md); calling it from another service, and verifying its tokens, is in [service-api.md](guides/service-api.md); the reasoning is in [design.md](design.md).

## Architecture

`auth-server` is built as a single Go modular monolith backed by PostgreSQL (`auth` schema). It relies on zero external identity providers, email gateways, or SMS aggregators.

```mermaid
flowchart TB
    subgraph Clients["Clients & Apps"]
        Mac["t10-mac-client (PKCE)"]
        Mobile["t10-mobile (P-256 Key Pair)"]
        Browser["t10-workbench / t10-console"]
    end

    subgraph AuthServer["auth-server (:8081)"]
        Guard["Route Guard & Auth Middleware"]
        IdSvc["identity.Service"]
        DirSvc["directory.Service"]
        AgentSvc["agents.Service"]
        RoleSvc["roles.Service"]
        Issuer["identity.Issuer (ES256)"]
    end

    subgraph Data["Storage"]
        PG[("PostgreSQL: auth schema & append-only audit")]
    end

    subgraph Platform["Internal Deployment (Audience: t10)"]
        LK["t10-livekit-agent"]
        ToolGW["ai-gateway-tools"]
        AgentHarness["agent-pi / agent-ti"]
        Modules["Business Microservices (property, collab, etc.)"]
    end

    Clients -->|HTTPS: Login / PKCE / Device Refresh| Guard
    Guard --> IdSvc & DirSvc & AgentSvc & RoleSvc
    IdSvc & DirSvc & AgentSvc & RoleSvc --> PG
    IdSvc --> Issuer

    Platform -->|JWKS Cache: /.well-known/jwks.json| Issuer
    Platform -->|Service Token: /v1/grants, /v1/org/*, /v1/entitlements| Guard
    ToolGW -->|Token Exchange: /v1/token| Guard
```

### Principles

1. **Self-Contained Credentials**: Accounts authenticate via username, phone number, or email combined with a password (Argon2id/bcrypt) and optional TOTP MFA. No outbound SMS or email verification exists; account recovery relies on pre-generated recovery codes or tenant/platform administrators.
2. **Static Client Registry**: OAuth clients and execution runtimes are statically defined in [`clients.yaml`](../clients.yaml) and reviewed in code. Dynamic client registration and user consent dialogs are intentionally omitted.
3. **Session as Refresh Token**: Refresh secrets rotate with every exchange and are stored directly in `auth.sessions` as cryptographic hashes (`secret_hash`, `prev_secret_hash`, `retired_secret_hashes`) with automatic replay detection.
4. **Single-Token Microservice Trust**: Internal microservices communicate in a single trust zone with a platform audience of `t10`. Dynamic agents never receive raw user tokens; they receive scoped, delegated tokens tied to an `agent_grants` record.
5. **Offline JWKS Verification**: Services verify tokens locally using ECDSA P-256 (`ES256`) public keys fetched from `/.well-known/jwks.json`, caching keys and grant chains without calling the auth server on every request.


## Code layout

The codebase is split into cohesive internal packages under `internal/`, two binaries in `cmd/`, and a public verifier package in `verifier/`:

```
auth-server/
├── cmd/
│   ├── auth-server/       # Service entrypoint (signal handling, HTTP server setup)
│   └── authctl/           # Operator CLI (bootstrapping, service accounts, keygen)
├── internal/
│   ├── agents/            # Runtime validation, grant hierarchy, room admission
│   ├── audit/             # Append-only audit logger (Actor, Scope, Action, Target)
│   ├── config/            # Environment variable loading and validation
│   ├── db/                # pgx connection pool and migration runner
│   ├── directory/         # Tenants, memberships, org units, and managers
│   ├── identity/          # Users, credentials, sessions, TOTP MFA, device keys, JWT issuer
│   ├── ids/               # Type-prefixed ID generator (usr_, ten_, grt_ and the rest in api.md)
│   ├── roles/             # Business role catalog, permission definitions, assignments
│   ├── samples/           # Dev-mode seed data and fixtures
│   ├── server/            # HTTP handlers, route guard matrix, HTML templates, i18n
│   └── telemetry/         # OpenTelemetry tracing setup (OTLP/HTTP)
├── verifier/              # Go offline token and grant chain verification library
│   └── ts/                # TypeScript/Node.js equivalent of the verifier
└── clients.yaml           # Reviewed client definitions, runtimes, and token exchangers
```


## Route access

Each route's access is one entry in the table in [`internal/server/server.go`](../internal/server/server.go), and a test fails for a route with none. The constants map to the access levels in [api.md](api.md#access):

| Constant | In api.md |
| --- | --- |
| `accessPublic` | Public |
| `accessPage` | Page |
| `accessBrowser` | Browser |
| `accessService` | Service |
| `accessUser` | User |
| `accessDevice` | Device |
| `accessTenantAdmin` | Tenant admin |
| `accessPlatformAdmin` | Platform admin, within `PlatformMFAWindow` (15 minutes) of a second factor |

A refused request fails closed and is written to `auth.audit_log`.

## Configuration

Configuration is parsed in [`internal/config/config.go`](../internal/config/config.go) via `config.Load(os.Getenv)`.

| Environment Variable | Required | Default | Description |
|---|---|---|---|
| `AUTH_PUBLIC_URL` | Yes | - | Public base URL and JWT `iss` claim (e.g. `http://localhost:8081` in dev, `https://auth.example.com` in prod). Outside dev mode, `https` is enforced. |
| `DATABASE_URL` | Yes | - | PostgreSQL connection URI (`postgres://user:pass@host:5432/db`). |
| `AUTH_CLIENTS_FILE` | Yes | - | Path to the YAML client and runtime registry (usually `clients.yaml`). |
| `AUTH_SIGNING_KEY_CURRENT`| Prod only | - | PEM-encoded P-256 private key for issuing JWTs. Generated via `authctl gen-key`. In dev mode, a random key is generated if unset. |
| `AUTH_SIGNING_KEY_NEXT` | No | - | PEM-encoded P-256 private key staged for key rotation. Published in JWKS alongside current. |
| `AUTH_TOTP_KEY` | Prod only | - | 32-byte base64 AES key for encrypting stored TOTP secrets (`authctl gen-totp-key`). In dev mode, defaults to an ephemeral key. |
| `AUTH_DEV_MODE` | No | `false` | Enables password grant, open registration, sample data commands, and localhost-only relaxation. |
| `AUTH_LISTEN_ADDR` | No | `:8081` | TCP address the HTTP server listens on. |
| `AUTH_PERMISSIONS_DIR` | No | - | Directory containing `<module>.yaml` catalog files defining business permissions and templates. |
| `AUTH_DEFAULT_REGION` | No | `CN` | Default ISO 3166-1 alpha-2 region for parsing phone numbers without country code. |
| `AUTH_TRUST_PROXY` | No | `false` | When `true`, takes client IP from the rightmost `X-Forwarded-For` entry added by an ingress reverse proxy. |
| `AUTH_SUPPORT_EMAIL` | No | unset | An email address the sign-in page shows under the links, as "Need help? Write to …". Unset, the page shows none |
| `AUTH_WAIVE_PLATFORM_MFA` | No | unset | `demo` lets a platform or tenant admin act without a second factor, as dev mode does, and changes nothing else. For a demo whose admin has no authenticator: anyone with that password has every tenant and user. Any other value is refused. It logs a warning at startup. Never set it in production |
| `AUTH_CONSOLE_URL` | No | - | Base URL for `t10-console` (platform admin redirection). |
| `AUTH_WORKBENCH_URL` | No | - | Base URL for `workbench` (tenant admin redirection). |
| `AUTH_APP_URLS` | No | - | Modules with their own web app, as `module=url` pairs separated by commas, for the landing page. Any other app link goes through Workbench. |
| `AUTH_LANGUAGES` | No | every language (`en,zh-Hans`) | The languages people can choose, comma separated, the default first. `zh-Hans` gives everyone Simplified Chinese with no choice. An unknown or repeated one stops the server. See [languages.md](languages.md). |
| `AUTH_TOOL_GATEWAY` | No | `false` | When `true`, runtimes with `tool_audience` in `clients.yaml` receive tokens valid only at `ai-gateway-tools`, and at `ai-gateway-llm` for a runtime with `model_audience`. |
| `LIVEKIT_URL` | Yes | - | URL of the LiveKit server instance. |
| `LIVEKIT_API_KEY` | Yes | - | LiveKit API Key used for room token generation. |
| `LIVEKIT_API_SECRET` | Yes | - | LiveKit API Secret used for signing room tokens (must be >= 32 characters in prod). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | - | Optional OTLP/HTTP URL (`http://collector:4318`) for distributed tracing. |



## Data model

All persistence lives in the `auth` PostgreSQL schema, managed by sequential SQL migrations in [`internal/db/migrations/`](../internal/db/migrations/).

IDs are a prefix and 32 hex characters, made by [`internal/ids`](../internal/ids/ids.go). The prefixes are listed in [api.md](api.md#conventions).

### Tables

```mermaid
erDiagram
    users ||--o{ user_identifiers : "identifies"
    users ||--o| credentials : "authenticates"
    users ||--o{ memberships : "belongs to"
    users ||--o{ sessions : "maintains"
    users ||--o{ devices : "owns"
    users ||--o| platform_admins : "granted"

    tenants ||--o{ memberships : "contains"
    tenants ||--o{ org_units : "structures"
    tenants ||--o{ tenant_roles : "defines"

    memberships ||--o{ member_role_assignments : "assigned"
    org_units ||--o{ org_units : "parent"
    memberships ||--o| org_units : "placed in"
    memberships ||--o| memberships : "reports to"

    service_accounts ||--o{ agent_grants : "executes"
    users ||--o{ agent_grants : "delegates"
    tenants ||--o{ agent_grants : "scoped to"
    agent_grants ||--o{ agent_grants : "child grant"

    permission_definitions ||--o{ role_permissions : "includes"
    tenant_roles ||--o{ role_permissions : "contains"
    tenant_roles ||--o{ member_role_assignments : "instantiates"
```

### Key tables and constraints

1. **`auth.users` & `auth.user_identifiers`**: A user has a `status` (`active`, `suspended`). Identifiers (`username`, `phone`, `email`) are normalized and strictly unique. Phones are stored in E.164 format.
2. **`auth.tenants` & `auth.memberships`**: Composite foreign keys `(tenant_id, user_id)` and `(tenant_id, id)` ensure cross-tenant references cannot occur in the database. A membership role is either `member` or `admin`.
3. **`auth.org_units` & `auth.memberships`**: Units are structured as an adjacency tree with `kind` (`department`, `team`). A member's `manager_id` points to another membership record within the same tenant, and so does a unit's optional `lead_id`. Admin tools set a member's manager to their unit's lead by default; the server stores only what they send.
4. **`auth.sessions`**: Tracks active client sessions. Stores `secret_hash` (current refresh token SHA-256), `prev_secret_hash` (to tolerate network drops on rotation), and `retired_secret_hashes` (replaying any retired hash triggers immediate session revocation).
5. **`auth.devices`**: Stores enrolled mobile hardware keys (`approval_public_key` and `session_public_key` as raw uncompressed P-256 points). `mfa_capable` is set only if enrolled with a second factor.
6. **`auth.agent_grants`**: Represents execution authorization for runtimes (`t10-livekit-agent`, `agent-pi`, etc.). Enforces a maximum chain depth of 4 (`depth BETWEEN 1 AND 4`). Supports triggers (`user`, `voice`, `schedule`, `event`, `webhook`, `agent`) and 90-day standing grants (`standing: true`).
7. **`auth.tenant_roles` & `auth.member_role_assignments`**: Module permissions are cataloged in `auth.permission_definitions`. Tenant admins compose roles from active permissions. Assignments are immutable; revoking sets `status = 'revoked'`. Any change increments `auth.tenants.authorization_revision`.
8. **`auth.audit_log`**: An immutable, append-only record of all security-sensitive actions. Protected at the schema level by PostgreSQL triggers (`audit_log_no_rewrite`, `audit_log_no_truncate`) preventing `UPDATE`, `DELETE`, or `TRUNCATE`.


## Tokens

Every token is signed with ES256 (ECDSA P-256, SHA-256) by `identity.Issuer` in [`internal/identity/tokens.go`](../internal/identity/tokens.go). A key's `kid` is the SHA-256 fingerprint of its uncompressed public key, and JWKS publishes `AUTH_SIGNING_KEY_NEXT` beside the current key so services know it before it signs. The claims of each kind are in [api.md](api.md#token-claims).

## Sign-in and grant flows

### 1. Authorization Code Flow with PKCE
Used by native and web apps (`t10-mac-client`, `workbench`, `console`).
1. Client starts a local loopback server (or uses a configured redirect URI) and generates a cryptographic `code_verifier` and its SHA-256 `code_challenge`.
2. Browser navigates to `GET /v1/authorize?client_id=...&response_type=code&redirect_uri=...&code_challenge=...&code_challenge_method=S256&state=...`.
3. If not signed in, user is redirected to `/v1/signin` and completes credentials/MFA.
4. Server issues a single-use authorization code and redirects to `redirect_uri?code=...&state=...`.
5. Client calls `POST /v1/token` with `grant_type=authorization_code`, `code`, and `code_verifier`.
6. Server returns `{ access_token, refresh_token, expires_in, token_type: "Bearer" }`.

### 2. Mobile Key-Pair Authentication
Used exclusively by `client_id: t10-mobile`.
- Device generates two P-256 keys in Secure Enclave / Android Keystore:
  - **Session Key**: Used silently for authentication and token refresh.
  - **Approval Key**: Biometric/Passcode-gated for signing sensitive actions (QR approvals, password updates).
- **Challenge Protocol**:
  1. Call `POST /v1/challenges` with `purpose: login | register | pair | refresh | approve | reauth`.
  2. Sign message: `"t10-device-v1\n<purpose>\n<challenge>\n<binding>"`.
  3. Send signature in Base64URL.
- **Refresh**: `POST /v1/token` with `grant_type=device_refresh`. No rotating secret is transmitted; the device signs the refresh challenge with its session private key.

### 3. Agent Grants & Dynamic Runs
1. **Root Grant**: A user session initiates a grant via `POST /v1/grants` providing `subject_token` (user access token), requested `actions`, and `audiences`. Default TTL is 8 hours (maximum lifetime 24 hours).
2. **Room Admission Grant**: On `POST /v1/rooms/admission`, room admission automatically generates a root grant for the voice runtime (`t10-livekit-agent`) with `trigger: voice`. The grant ID is embedded in the LiveKit room participant token under `t10.grant`.
3. **Child Grant**: A runtime presents its delegated token as `subject_token` to `POST /v1/grants` to spawn a sub-agent. The child can only restrict actions/audiences and cannot outlive the parent. Chain depth is capped at 4.
4. **Token Minting**: The runtime calls `POST /v1/token` with `grant_type=agent_grant`, its `client_id`, `client_secret`, and `grant_id`. The server re-verifies the entire chain up to the user before issuing a token.
5. **Standing Grants**: Long-term consent for automations created via `POST /v1/grants` with `standing: true` by `t10-automations`. Valid for 90 days, auto-renewed when the user refreshes their session. Fired via `parent_id` with triggers (`schedule`, `event`, `webhook`).

### 4. Token Exchange
`ai-gateway-tools` trades a run's token for a module-specific token:
- `POST /v1/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`.
- Parameters: `client_id`, `client_secret`, `subject_token`, `audience`.
- Only callers listed under `exchangers` in `clients.yaml` can perform this exchange.


## Verification in other services

Services verify tokens with [`verifier/`](../verifier) in Go or [`verifier/ts/verifier.ts`](../verifier/ts/verifier.ts), never by reading `sub`; [service-api.md](guides/service-api.md) shows how. Every other service holds a copy of `verifier/`, which the workspace's `scripts/check-contracts.sh` compares.

| Token | `UserID` | `ServiceID` | `Agent` | `Allows(action)` |
|---|---|---|---|---|
| User access token (`aud: ["t10"]`) | Set | Empty | `nil` | Always true: the service judges the person's rights |
| Delegated agent token (`aud: [service]`) | Set | Empty | Set | True only when the action is in the token and on every grant in the chain |
| Service token (`aud: ["t10"]`) | Empty | Set | `nil` | Always false |

- **Grant chains are cached for 60 seconds** and JWKS for 10 minutes, so a revoked grant stops working downstream within a minute.
- **Fail closed.** When a delegated token's chain can't be fetched, `Verify` returns `ErrGrantUnavailable`, and the service refuses.

## authctl

The [`authctl`](../cmd/authctl/main.go) tool runs administrative and operator commands against `DATABASE_URL`.

### Commands

```sh
# 1. Cryptographic Key Management
authctl gen-key              # Generate ES256 P-256 private key PEM
authctl gen-totp-key         # Generate 32-byte base64 key for AUTH_TOTP_KEY

# 2. System Bootstrapping
authctl bootstrap \
  --username root \
  --tenant-id ten_acme \
  --tenant-name "Acme Corp"
# Prompts for password via AUTHCTL_PASSWORD or stdin.
# Creates the tenant, user, membership, and grants platform admin.

# 3. User Management
authctl add-user \
  --username alice \
  --tenant-id ten_acme \
  --role member             # "member" or "admin"

# 4. Service Account Lifecycle (Zero-Downtime Secret Rotation)
authctl service-add --name agent-pi       # Registers service and outputs secret
authctl service-rotate --name agent-pi    # Adds secondary secret; both now work
authctl service-finish --name agent-pi    # Removes previous secret
authctl service-disable --name agent-pi   # Immediately revokes access & all grants
authctl service-enable --name agent-pi    # Re-enables service account

# 5. Permission Catalog Maintenance
authctl permissions-purge \
  --module property \
  --confirm property
# Purges retired module permissions from all tenant roles (requires module removed from config).

# 6. Mini-program binding
authctl wechat-unbind --user-id usr_…   # Removes a person's WeChat binding

# 7. Sample Data (Dev Mode Only)
authctl samples-add          # Seeds test tenants, users, and org units
authctl samples-remove       # Cleans up test fixtures

# 8. Tenants and invitations
authctl tenant-add --tenant-id ten_contoso --tenant-name Contoso [--if-missing]
authctl invite --tenant-id ten_contoso --role admin   # prints invite_url (register) and join_url, 7 days, single use
authctl tenant-suspend --tenant-id ten_contoso         # no sign-in to it, its invitations stop working
authctl tenant-activate --tenant-id ten_contoso

# 9. Demo start links (a demo only; needs DEMO_START_KEY, 32+ characters)
authctl demo-link --tenant-id ten_contoso-x7k2 --company Contoso --name "Jane Doe" --days 30
authctl demo-start --domain demo.example     # serves /demo/start on :8090
```

**Demo start links.** For a public demo, an outreach email carries a link signed with `DEMO_START_KEY` that names a tenant still to be made. `demo-start` serves it: opening the link only shows a Start button, because mail scanners open every link in a message. Start makes the tenant and five teammates (`bob@<tenant>.<domain>` and the rest, members, with random passwords shown once), then sends the prospect to register as its admin with an invitation. Starting again before registering gives a new invitation; after, it points to sign-in; a suspended tenant shows that the demo has ended. `invite` and `tenant-suspend` work without it. The workspace's `deploy/edge/demo` runs it behind the auth host's `/demo/` path.


## Running it locally

### Docker Compose

```sh
cd auth-server
docker compose up --build
```
This spins up:
1. PostgreSQL on `:5432` with automatic database migrations applied.
2. `auth-server` listening on `:8081` in dev mode.
3. Pre-seeded platform admin:
   - **Username**: `ada@acme.example`
   - **Password**: `change-me-enterprise-admin`
   - **Tenant**: `ten_acme`

### Tests

```sh
cd auth-server
go test -v ./...
```
Tests that need Postgres run only with `TEST_DATABASE_URL` set. Each rebuilds the `auth` schema there, so never point it at a real database. Without it they skip, and the rest still run. The TypeScript verifier has its own: `node --test verifier/ts/verifier.test.ts`.

## Troubleshooting

### 1. `401 Unauthorized` on Room Join
- **Cause**: `LIVEKIT_API_SECRET` mismatch between `auth-server` and `t10-livekit-agent`.
- **Fix**: Ensure identical secrets in both `.env` configurations.

### 2. LiveKit Agent and Mac Client Never Meet
- **Cause**: Room namespacing mismatch.
- **Fix**: Admission prefixes the room name with `<tenant_id>__`. If `t10-mac-client` joins `demo`, the real LiveKit room is `ten_acme__demo`. Ensure `t10-livekit-agent` connects using `-room ten_acme__demo`.

### 3. Server Refuses to Start (`runtime ... has no service account`)
- **Cause**: `clients.yaml` lists an execution runtime under `runtimes`, but no corresponding row exists in `auth.service_accounts`.
- **Fix**: Run `authctl service-add --name <runtime-name>`.

### 4. `409 Conflict: mfa_needed`
- **Cause**: Tenant administrator attempted to enable `require_mfa` on a tenant, but their current session has not satisfied MFA.
- **Fix**: Enroll in TOTP MFA under `/v1/account` or sign in with a second factor before enabling tenant-wide MFA enforcement.

### 5. `409 Conflict: stale_revision`
- **Cause**: Optimistic concurrency failure during tenant role or assignment updates.
- **Fix**: Re-fetch the role or assignment to read the latest `revision` number and retry the modification.

### 6. `403 Forbidden` on Entitlements Read
- **Cause**: A microservice attempted to read `/v1/entitlements` for a module other than the one declared in its catalog manifest (`service` property in `<module>.yaml`).
- **Fix**: Ensure the service token belongs to the service designated for that module.
