# Auth Server Developer Reference

The `auth-server` is the sole identity authority and JWT issuer for the t10 platform. It manages accounts, credentials, multi-tenant memberships, organization structures, device keys, agent execution grants, and business role catalogs. Downstream services and client applications verify its tokens offline against its JSON Web Key Set (JWKS).

---

## Table of Contents

1. [Architecture & System Design](#architecture--system-design)
2. [Codebase Organization](#codebase-organization)
3. [Configuration & Environment](#configuration--environment)
4. [Data Model & Schema](#data-model--schema)
5. [Token & Key Architecture](#token--key-architecture)
6. [Authentication & Grant Flows](#authentication--grant-flows)
7. [End-to-End Walkthrough: Flow, Token Claims & Usage](#end-to-end-walkthrough-flow-token-claims--usage)
8. [API Route Reference](#api-route-reference)
9. [Downstream Verification (Go & TypeScript)](#downstream-verification-go--typescript)
10. [Operator CLI: authctl](#operator-cli-authctl)
11. [Local Development & Testing](#local-development--testing)
12. [Troubleshooting & Common Failure Modes](#troubleshooting--common-failure-modes)

---

## Architecture & System Design

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
        AgentHarness["agent-pi / agent-sales / agent-ti"]
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

### Core Design Principles

1. **Self-Contained Credentials**: Accounts authenticate via username, phone number, or email combined with a password (Argon2id/bcrypt) and optional TOTP MFA. No outbound SMS or email verification exists; account recovery relies on pre-generated recovery codes or tenant/platform administrators.
2. **Static Client Registry**: OAuth clients and execution runtimes are statically defined in [`clients.yaml`](../clients.yaml) and reviewed in code. Dynamic client registration and user consent dialogs are intentionally omitted.
3. **Session as Refresh Token**: Refresh secrets rotate with every exchange and are stored directly in `auth.sessions` as cryptographic hashes (`secret_hash`, `prev_secret_hash`, `retired_secret_hashes`) with automatic replay detection.
4. **Single-Token Microservice Trust**: Internal microservices communicate in a single trust zone with a platform audience of `t10`. Dynamic agents never receive raw user tokens; they receive scoped, delegated tokens tied to an `agent_grants` record.
5. **Offline JWKS Verification**: Services verify tokens locally using ECDSA P-256 (`ES256`) public keys fetched from `/.well-known/jwks.json`, caching keys and grant chains without calling the auth server on every request.

---

## Codebase Organization

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
│   ├── db/                # pgx connection pool and migration runner (0001-0008)
│   ├── directory/         # Tenants, memberships, org units, and managers
│   ├── identity/          # Users, credentials, sessions, TOTP MFA, device keys, JWT issuer
│   ├── ids/               # Type-prefixed ID generator (e.g. usr_, ten_, agnt_)
│   ├── roles/             # Business role catalog, permission definitions, assignments
│   ├── samples/           # Dev-mode seed data and fixtures
│   ├── server/            # HTTP handlers, route guard matrix, HTML templates, i18n
│   └── telemetry/         # OpenTelemetry tracing setup (OTLP/HTTP)
├── verifier/              # Go offline token and grant chain verification library
│   └── ts/                # TypeScript/Node.js equivalent of the verifier
└── clients.yaml           # Reviewed client definitions, runtimes, and token exchangers
```

---

## Configuration & Environment

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
| `AUTH_CONSOLE_URL` | No | - | Base URL for `t10-console` (platform admin redirection). |
| `AUTH_WORKBENCH_URL` | No | - | Base URL for `workbench` (tenant admin redirection). |
| `AUTH_TOOL_GATEWAY` | No | `false` | When `true`, runtimes with `tool_audience` in `clients.yaml` receive tokens valid only at `ai-gateway-tools`, and at `ai-gateway-llm` for a runtime with `model_audience`. |
| `LIVEKIT_URL` | Yes | - | URL of the LiveKit server instance. |
| `LIVEKIT_API_KEY` | Yes | - | LiveKit API Key used for room token generation. |
| `LIVEKIT_API_SECRET` | Yes | - | LiveKit API Secret used for signing room tokens (must be >= 32 characters in prod). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | - | Optional OTLP/HTTP URL (`http://collector:4318`) for distributed tracing. |

---

## Data Model & Schema

All persistence lives in the `auth` PostgreSQL schema, managed by sequential SQL migrations in [`internal/db/migrations/`](../internal/db/migrations/).

### ID Prefixes

Identities are prefixed random 16-byte hex strings generated by [`internal/ids`](../internal/ids/ids.go):

| Prefix | Entity | Example |
|---|---|---|
| `usr_` | User account | `usr_9a4f2b18c0e27189...` |
| `ten_` | Tenant organization | `ten_acme` (slug format `^ten_[a-z0-9-]+$`) |
| `mem_` | Membership link | `mem_8d1a4e23...` |
| `ses_` | User session | `ses_71c4fa90...` |
| `dev_` | Enrolled mobile device | `dev_54e12c01...` |
| `svc_` | Service account | `svc_agent-pi` |
| `agnt_` | Agent execution grant | `agnt_3e98ab42...` |
| `unit_` | Org unit (department/team) | `unit_01fa49c3...` |
| `role_` | Tenant business role | `role_8b72e104...` |
| `asgn_` | Role assignment | `asgn_99c301fe...` |
| `jti_` | JWT unique ID | `jti_118fa302...` |

### Database Tables Overview

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

#### Key Tables & Constraints

1. **`auth.users` & `auth.user_identifiers`**: A user has a `status` (`active`, `suspended`). Identifiers (`username`, `phone`, `email`) are normalized and strictly unique. Phones are stored in E.164 format.
2. **`auth.tenants` & `auth.memberships`**: Composite foreign keys `(tenant_id, user_id)` and `(tenant_id, id)` ensure cross-tenant references cannot occur in the database. A membership role is either `member` or `admin`.
3. **`auth.org_units` & `auth.memberships`**: Units are structured as an adjacency tree with `kind` (`department`, `team`). A member's `manager_id` points to another membership record within the same tenant, and so does a unit's optional `lead_id`. Admin tools set a member's manager to their unit's lead by default; the server stores only what they send.
4. **`auth.sessions`**: Tracks active client sessions. Stores `secret_hash` (current refresh token SHA-256), `prev_secret_hash` (to tolerate network drops on rotation), and `retired_secret_hashes` (replaying any retired hash triggers immediate session revocation).
5. **`auth.devices`**: Stores enrolled mobile hardware keys (`approval_public_key` and `session_public_key` as raw uncompressed P-256 points). `mfa_capable` is set only if enrolled with a second factor.
6. **`auth.agent_grants`**: Represents execution authorization for runtimes (`t10-livekit-agent`, `agent-pi`, etc.). Enforces a maximum chain depth of 4 (`depth BETWEEN 1 AND 4`). Supports triggers (`user`, `voice`, `schedule`, `event`, `webhook`, `agent`) and 90-day standing grants (`standing: true`).
7. **`auth.tenant_roles` & `auth.member_role_assignments`**: Module permissions are cataloged in `auth.permission_definitions`. Tenant admins compose roles from active permissions. Assignments are immutable; revoking sets `status = 'revoked'`. Any change increments `auth.tenants.authorization_revision`.
8. **`auth.audit_log`**: An immutable, append-only record of all security-sensitive actions. Protected at the schema level by PostgreSQL triggers (`audit_log_no_rewrite`, `audit_log_no_truncate`) preventing `UPDATE`, `DELETE`, or `TRUNCATE`.

---

## Token & Key Architecture

`auth-server` signs all tokens using **ECDSA P-256 with SHA-256** (`ES256`).

### JWKS (`GET /.well-known/jwks.json`)
Public keys are published in standard JWKS format. Each key exposes:
- `kty`: `"EC"`
- `crv`: `"P-256"`
- `alg`: `"ES256"`
- `use`: `"sig"`
- `kid`: SHA-256 fingerprint of the uncompressed public key.
- `x`, `y`: Base64URL-encoded coordinates.

### Access Token Claims

All access tokens expire in **5 minutes** (`AccessTokenTTL = 5 * time.Minute`).

```json
{
  "iss": "http://localhost:8081",
  "sub": "usr_9a4f2b18c0e27189...",
  "aud": ["t10"],
  "exp": 1793910000,
  "iat": 1793909700,
  "jti": "jti_118fa302...",
  "tid": "ten_acme",
  "scope": "agent:use",
  "sid": "ses_71c4fa90..."
}
```

### Delegated (Agent) Token Claims

Minted via `POST /v1/token` with `grant_type=agent_grant` or token exchange:
```json
{
  "iss": "http://localhost:8081",
  "sub": "usr_9a4f2b18c0e27189...",
  "aud": ["agent-pi", "t10-collab"],
  "exp": 1793910000,
  "iat": 1793909700,
  "jti": "jti_98bc7211...",
  "tid": "ten_acme",
  "scope": "agent:use work:read work:write",
  "act": {
    "sub": "svc_agent-pi"
  },
  "grant": "agnt_3e98ab42...",
  "trg": "user",
  "automation": ""
}
```
- `aud`: List of specific target services (never includes `"t10"`, preventing replay against the platform or other user APIs).
- `act.sub`: Service account ID of the executing runtime.
- `grant`: Execution grant ID in `auth.agent_grants`.
- `trg`: The run trigger (`user`, `voice`, `schedule`, `event`, `webhook`, `agent`).
- `automation`: Automation identifier if triggered by `t10-automations`.

### Service Token Claims

Minted via `grant_type=client_credentials`:
```json
{
  "iss": "http://localhost:8081",
  "sub": "svc_agent-pi",
  "aud": ["t10"],
  "exp": 1793910000,
  "iat": 1793909700,
  "jti": "jti_5510de33..."
}
```
Has no `tid`, `scope`, or `sid`. Used strictly for service-to-service administration (grants, org reads, entitlements).

---

## Authentication & Grant Flows

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

---

## End-to-End Walkthrough: Flow, Token Claims & Usage

This concrete scenario walks through how a human user signs in, how delegation bounds an AI agent, what each JWT looks like on the wire, and how downstream microservices enforce permissions.

### The Scenario
**Alice** (`usr_alice`) belongs to tenant **Acme Corp** (`ten_acme`). She opens `t10-mac-client` to run an interactive research task. The client delegates work to the `agent-pi` runtime, which reads documents from the `t10-collab` microservice.

```mermaid
sequenceDiagram
    autonumber
    actor Alice
    participant Client as t10-mac-client
    participant Auth as auth-server (:8081)
    participant Agent as agent-pi runtime
    participant Service as t10-collab

    %% Phase 1: User Login
    Note over Alice, Auth: 1. User Sign-In (OAuth PKCE)
    Client->>Auth: GET /v1/authorize?client_id=t10-mac-client&code_challenge=...
    Alice->>Auth: Authenticates at /v1/signin (Password / MFA)
    Auth-->>Client: Redirect to callback with authorization code
    Client->>Auth: POST /v1/token (grant_type=authorization_code, code_verifier=...)
    Auth-->>Client: User Access Token (aud: ["t10"], sub: usr_alice) + Refresh Token

    %% Phase 2: Agent Delegation
    Note over Client, Agent: 2. Create Execution Grant
    Client->>Auth: POST /v1/grants (subject_token: User Token, actions: ["work:read"], audiences: ["t10-collab"])
    Auth-->>Client: Returns grant_id: agnt_98ac0145...
    Client->>Agent: Dispatches prompt + grant_id

    %% Phase 3: Agent Mints Token
    Note over Agent, Auth: 3. Mint Delegated Token
    Agent->>Auth: POST /v1/token (grant_type=agent_grant, grant_id: agnt_98ac0145..., client_secret: ...)
    Auth-->>Agent: Delegated Token (aud: ["t10-collab"], act.sub: svc_agent-pi)

    %% Phase 4: API Call & Verification
    Note over Agent, Service: 4. Downstream Call & Verification
    Agent->>Service: GET /v1/documents (Authorization: Bearer <Delegated Token>)
    Service->>Auth: GET /.well-known/jwks.json (cached 10 min)
    Service->>Auth: GET /v1/grants/agnt_.../chain (cached 60 sec)
    Service-->>Agent: HTTP 200 OK (scoped to usr_alice in ten_acme)
```

### Step 1: User Login (PKCE Flow)
1. `t10-mac-client` generates a random `code_verifier` and SHA-256 `code_challenge`.
2. It opens the system browser to `/v1/authorize`. Alice signs in at `/v1/signin`.
3. `auth-server` redirects to `http://127.0.0.1:<port>/callback?code=<code>`.
4. `t10-mac-client` calls `POST /v1/token`:
   ```http
   POST /v1/token HTTP/1.1
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code
   &client_id=t10-mac-client
   &code=cde_3f1a08...
   &code_verifier=dBjftJeZ4CVP-8BspPKbfUqlEchu...
   &redirect_uri=http://127.0.0.1:52134/callback
   ```
5. `auth-server` returns:
   - `access_token`: 5-minute ES256 JWT.
   - `refresh_token`: Opaque string backed by a session row with cryptographic hash chaining.

### Step 2: Creating an Agent Grant
Before invoking `agent-pi`, the client asks `auth-server` to create an execution grant bounded by user, tenant, actions, and audiences:
```http
POST /v1/grants HTTP/1.1
Authorization: Bearer <User Access Token>
Content-Type: application/json

{
  "actions": ["work:read"],
  "audiences": ["t10-collab"],
  "ttl_seconds": 28800
}
```
`auth-server` verifies Alice's token, validates that `actions` and `audiences` are permitted for the runtime in `clients.yaml`, and creates a row in `auth.agent_grants` returning `{ "id": "agnt_98ac0145ba89fe21", "expires_at": "..." }`. The client gives this `grant_id` to `agent-pi`.

### Step 3: Minting the Delegated Token
`agent-pi` authenticates with its own runtime credentials and exchanges the grant for an execution token:
```http
POST /v1/token HTTP/1.1
Content-Type: application/json

{
  "grant_type": "agent_grant",
  "client_id": "agent-pi",
  "client_secret": "dev-only-agent-pi-service-secret-change-me",
  "grant_id": "agnt_98ac0145ba89fe21"
}
```
`auth-server` verifies that:
1. `agent-pi` is an active service account in `auth.service_accounts`.
2. The grant exists, is not revoked, has not expired, and was assigned to `agent-pi`.
3. Alice's membership in `ten_acme` and account are still `active`.

It mints a 5-minute delegated token specifically targeted to `["t10-collab"]`.

---

### Token Anatomy: What Is Inside the JWTs

All tokens are signed with ECDSA P-256 (`ES256`). Notice how claims strictly separate user access from agent execution:

#### 1. User Access Token
Carried by the client app for user-initiated actions:
```json
{
  "iss": "http://localhost:8081",
  "sub": "usr_alice",
  "aud": ["t10"],
  "exp": 1793910000,
  "iat": 1793909700,
  "jti": "jti_118fa30209ae881a",
  "tid": "ten_acme",
  "sid": "ses_71c4fa9012cd33b4",
  "scope": "agent:use"
}
```
- **`sub`**: `usr_alice` (the human user).
- **`aud: ["t10"]`**: Broad platform audience. Accepted by user profile and admission routes, but rejected by backend microservices.
- **`tid`**: Tenant ID `ten_acme`.
- **`sid`**: Active session identifier used to track and revoke web/native sessions.

#### 2. Delegated Agent Token
Carried by the agent runtime when invoking downstream microservices:
```json
{
  "iss": "http://localhost:8081",
  "sub": "usr_alice",
  "aud": ["t10-collab"],
  "exp": 1793910000,
  "iat": 1793909700,
  "jti": "jti_4490cdb109af321e",
  "tid": "ten_acme",
  "scope": "work:read",
  "act": {
    "sub": "svc_agent-pi"
  },
  "grant": "agnt_98ac0145ba89fe21",
  "trg": "user",
  "automation": ""
}
```
- **`aud: ["t10-collab"]`**: Narrow audience. Cannot be replayed against other microservices or `auth-server`.
- **`act.sub`**: Identifies the acting runtime (`svc_agent-pi`).
- **`grant`**: References the live grant row in `auth.agent_grants`.
- **`scope`**: Limits the agent to `work:read` (cannot write or delete).
- **`trg`**: Trigger origin (`user`, `voice`, `schedule`, `event`, `webhook`).

---

### Step 4: How Downstream Services Verify and Use the Token

When `t10-collab` receives `GET /v1/documents` with `Authorization: Bearer <Delegated Token>`, it checks the token using the `verifier` library:

```go
package main

import (
    "net/http"
    "t10-auth-server/verifier"
)

func DocumentsHandler(v *verifier.Verifier) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // 1. Extract Bearer token from request
        bearer := r.Header.Get("Authorization")

        // 2. Offline cryptographic check + grant chain verification
        who, err := v.Verify(r.Context(), bearer)
        if err != nil {
            http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
            return
        }

        // 3. Action Authorization: ensure the grant explicitly includes this action
        if !who.Allows("work:read") {
            http.Error(w, "Forbidden: missing work:read permission", http.StatusForbidden)
            return
        }

        // 4. Multi-Tenant Isolation: bind database queries to the verified tenant and user
        tenantID := who.TenantID  // "ten_acme"
        userID := who.UserID      // "usr_alice"

        // 5. Inspect Agent Context (if executed by an agent)
        if who.IsAgent() {
            actingRuntime := who.Agent.Runtime  // "svc_agent-pi"
            trigger := who.Agent.Trigger        // "user"
            grantID := who.Agent.GrantID        // "agnt_98ac0145ba89fe21"
            // Optionally inspect any custom constraints attached to the grant
        }

        // 6. Safe database query: WHERE tenant_id = tenantID AND owner_id = userID
        // ...
    }
}
```

#### Why This Works
1. **Local Verification**: The public key is retrieved from `GET /.well-known/jwks.json` and cached in-memory for 10 minutes. Cryptographic signature checks are pure CPU operations with zero network overhead.
2. **Revocation Within 60 Seconds**: For delegated tokens, `verifier` caches the grant chain for 60 seconds. If an admin revokes `agnt_98ac...`, all downstream calls fail within a minute, even though the JWT expires in 5 minutes.
3. **No Credential Exposure**: The user's password, refresh token, and platform-level credentials never touch `agent-pi` or `t10-collab`.

---

## API Route Reference

Every route's access level is checked by the server guard matrix in [`internal/server/server.go`](../internal/server/server.go). Requests failing access checks fail closed and log to `auth.audit_log`.

### Guard Matrix Legend

- `accessPublic`: No credentials required.
- `accessPage`: Hosted HTML pages; POST requests require same-origin header verification.
- `accessBrowser`: Signed-in browser session (redirects to `/v1/signin` if unauthenticated).
- `accessService`: Bearer service token from `client_credentials`.
- `accessUser`: Any valid user access token (`aud: ["t10"]`).
- `accessDevice`: Mobile device session token with associated `device_id`.
- `accessTenantAdmin`: Administrator of tenant `{id}` (or platform admin).
- `accessPlatformAdmin`: Platform admin whose session proved a second factor within 15 minutes (`PlatformMFAWindow`).

### Complete Endpoint Map

#### Public & System
| Method | Route | Access | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | `accessPublic` | Liveness probe (`200 ok`). |
| `GET` | `/readyz` | `accessPublic` | Readiness probe (verifies database pool connectivity). |
| `GET` | `/.well-known/jwks.json` | `accessPublic` | JSON Web Key Set with active and staged public keys. |
| `POST` | `/v1/token` | `accessPublic` | Token endpoint (`authorization_code`, `refresh_token`, `client_credentials`, `agent_grant`, `device_refresh`, `token-exchange`). |
| `POST` | `/v1/revoke` | `accessPublic` | Revokes a refresh token (`token`, `client_id`, `client_secret`). |

#### Mobile Device Sign-In & Pairing
| Method | Route | Access | Purpose |
|---|---|---|---|
| `POST` | `/v1/challenges` | `accessPublic` | Get a 2-minute cryptographic challenge for a purpose. |
| `POST` | `/v1/login` | `accessPublic` | Mobile direct login with password and device key signature. |
| `POST` | `/v1/login/mfa` | `accessPublic` | Submit TOTP code during device enrollment. |
| `POST` | `/v1/login/register` | `accessPublic` | Mobile direct account registration (invite-only outside dev mode). |
| `POST` | `/v1/login/recover` | `accessPublic` | Account recovery using recovery codes. |
| `POST` | `/v1/login/pair` | `accessPublic` | Initiate QR pairing on a secondary device. |
| `POST` | `/v1/login/pair/poll` | `accessPublic` | Poll pairing status until approved. |

#### Hosted Web Pages & Auth
| Method | Route | Access | Purpose |
|---|---|---|---|
| `GET` | `/v1/authorize` | `accessPage` | OAuth 2.0 PKCE authorization handler. |
| `GET` / `POST` | `/v1/signin` | `accessPage` | Hosted sign-in page and credential verification. |
| `GET` | `/v1/signout/complete` | `accessPage` | Spends a sign-out ticket: ends the browser sign-in and its web apps, then returns to the app. |
| `GET` | `/v1/signout` | `accessPage` | Asks "Sign out of t10?", for an app with no session left to get a ticket. |
| `POST` | `/v1/signout` | `accessPage` | Sign out the browser session and every web app's session started from it. |
| `POST` | `/v1/signin/qr` | `accessPage` | Generate QR code payload for mobile sign-in. |
| `POST` | `/v1/signin/qr/poll` | `accessPage` | Poll status of QR sign-in. |
| `GET` / `POST` | `/v1/register` | `accessPage` | Hosted registration page (invite-only in prod). |
| `GET` / `POST` | `/v1/recover` | `accessPage` | Password recovery page via recovery codes. |
| `GET` / `POST` | `/v1/reset` | `accessPage` | Password reset handler using admin-generated link. |
| `POST` | `/v1/language` | `accessPage` | Set UI language cookie (`en` or `zh-CN`). |
| `GET` / `POST` | `/v1/account` | `accessBrowser` | User account management portal. |
| `GET` / `POST` | `/v1/join` | `accessBrowser` | Accept a tenant invitation link. |
| `GET` | `/admin` | `accessBrowser` | Redirect to `t10-console` or `workbench` based on user role. |

#### User APIs
| Method | Route | Access | Purpose |
|---|---|---|---|
| `POST` | `/v1/rooms/admission`| `accessUser` | Mint LiveKit room token & create voice agent grant. |
| `GET` | `/v1/me` | `accessUser` | Current user profile, active tenant, and memberships. |
| `GET` | `/v1/me/access` | `accessUser` | Effective platform and tenant admin rights, and `managed_agents`: the agent accounts the caller manages, whose runs' approvals they may decide. |
| `GET` | `/v1/me/session` | `accessUser` | 200 while the session behind the token stands. Apps ask it to notice a sign-out elsewhere. |
| `POST` | `/v1/me/browser-logout` | `accessUser` | A one-minute ticket that ends the browser sign-in behind this session, for a registered `/signed-out` return. |
| `GET` | `/v1/me/permissions` | `accessUser` | Active business permissions in the active tenant. |
| `PATCH` | `/v1/me` | `accessUser` | Update display name. |
| `POST` | `/v1/logout` | `accessUser` | Revoke current user session. |

#### Mobile Device Session Management
| Method | Route | Access | Purpose |
|---|---|---|---|
| `POST` | `/v1/qr/{id}/claim` | `accessDevice` | Claim a scanned QR login session. |
| `POST` | `/v1/qr/{id}/approve` | `accessDevice` | Approve a QR login (signed with Approval key). |
| `POST` | `/v1/qr/{id}/deny` | `accessDevice` | Deny a QR login. |
| `POST` | `/v1/me/password` | `accessDevice` | Change password (requires approval signature). |
| `POST` | `/v1/me/names` | `accessDevice` | Bind a new username, phone, or email. |
| `POST` | `/v1/me/names/remove` | `accessDevice` | Remove an identifier. |
| `POST` | `/v1/me/totp/start` | `accessDevice` | Begin TOTP setup (returns QR and secret). |
| `POST` | `/v1/me/totp/confirm`| `accessDevice` | Confirm and activate TOTP. |
| `POST` | `/v1/me/totp/disable`| `accessDevice` | Disable TOTP (requires approval signature). |
| `POST` | `/v1/me/recovery-codes`| `accessDevice` | Regenerate recovery codes. |
| `POST` | `/v1/me/signout-all` | `accessDevice` | Invalidate all sessions except current device. |
| `POST` | `/v1/me/invitations/accept` | `accessDevice` | Accept a tenant invite from mobile. |
| `POST` | `/v1/devices/{id}/revoke` | `accessDevice` | Revoke an enrolled device. |

#### Service-to-Service APIs
| Method | Route | Access | Purpose |
|---|---|---|---|
| `POST` | `/v1/grants` | `accessService` | Create root grant, child grant, or standing grant. |
| `GET` | `/v1/grants/{id}/chain`| `accessService` | Retrieve active grant hierarchy and constraints. |
| `POST` | `/v1/grants/{id}/extend`| `accessService`| Extend grant TTL with fresh user token. |
| `POST` | `/v1/grants/{id}/revoke`| `accessService`| Revoke grant and all subordinate child grants. |
| `GET` | `/v1/org/units` | `accessService` | List tenant organizational units. |
| `GET` | `/v1/org/units/{id}/members` | `accessService` | List members of an org unit (transitive option). |
| `GET` | `/v1/org/members` | `accessService` | Cursor-paginated list of tenant members. |
| `GET` | `/v1/org/members/{id}`| `accessService` | Get member details, manager link, and unit placement. |
| `GET` | `/v1/org/members/{id}/reports` | `accessService` | List direct and transitive managerial reports. |
| `GET` | `/v1/entitlements` | `accessService` | Bulk query member business roles and permissions. |

#### Tenant Administration (`/v1/tenants/{id}/*`)
| Method | Route | Access | Purpose |
|---|---|---|---|
| `GET` / `PATCH`| `/v1/tenants/{id}` | `accessTenantAdmin` | Read or update tenant settings (`name`, `require_mfa`). |
| `GET` | `/v1/tenants/{id}/members` | `accessTenantAdmin` | List tenant members, roles, managers, and units. |
| `PATCH` | `/v1/tenants/{id}/members/{user}` | `accessTenantAdmin` | Update member status or role (`member`, `admin`). |
| `POST` | `/v1/tenants/{id}/members/{user}/reset-link` | `accessTenantAdmin` | Generate password reset link (single-tenant accounts only). |
| `POST` | `/v1/tenants/{id}/invitations` | `accessTenantAdmin` | Create an invitation token for a new member. |
| `GET` / `POST` | `/v1/tenants/{id}/units` | `accessTenantAdmin` | List or create organizational units. |
| `PUT` / `DELETE`| `/v1/tenants/{id}/units/{unit}` | `accessTenantAdmin` | Update an org unit (name, kind, parent, lead) or delete it. `DELETE ?move=up` first moves its members and child units to its parent. |
| `GET` / `PUT` | `/v1/tenants/{id}/members/{user}/placement` | `accessTenantAdmin` | Read or set member's unit and manager placement. |
| `PUT` | `/v1/tenants/{id}/placements` | `accessTenantAdmin` | Place up to 500 members in one change, all or none, with an audit row each. |
| `POST` | `/v1/tenants/{id}/agent-accounts` | `accessTenantAdmin` | Create a tenant agent account, with no sign-in, placed under an optional manager and unit. |
| `PATCH` | `/v1/tenants/{id}/agent-accounts/{user}` | `accessTenantAdmin` | Rename an agent account. A person's name isn't an admin's to change. |
| `GET` | `/v1/tenants/{id}/grants` | `accessTenantAdmin` | List running agent grants in the tenant. |
| `POST` | `/v1/tenants/{id}/grants/{grant}/revoke` | `accessTenantAdmin` | Terminate an active agent grant. |
| `GET` | `/v1/tenants/{id}/audit` | `accessTenantAdmin` | View tenant-scoped audit event log. |
| `GET` | `/v1/tenants/{id}/permission-catalog` | `accessTenantAdmin` | Deployed modules and available business permissions. |
| `GET` / `POST` | `/v1/tenants/{id}/roles` | `accessTenantAdmin` | List or create custom tenant roles. |
| `GET` / `PATCH`| `/v1/tenants/{id}/roles/{role}` | `accessTenantAdmin` | Read or edit role permissions (requires `revision`). |
| `GET` / `POST` | `/v1/tenants/{id}/members/{user}/role-assignments` | `accessTenantAdmin` | List or assign roles to a member. |
| `DELETE` | `/v1/tenants/{id}/members/{user}/role-assignments/{assignment}` | `accessTenantAdmin` | Revoke a role assignment (requires `revision`). |

#### Platform Administration
| Method | Route | Access | Purpose |
|---|---|---|---|
| `GET` / `POST` | `/v1/tenants` | `accessPlatformAdmin` | List all tenants or create a new tenant. |
| `POST` | `/v1/tenants/{id}/suspend` | `accessPlatformAdmin` | Suspend tenant (locks out all members). |
| `POST` | `/v1/tenants/{id}/activate`| `accessPlatformAdmin` | Reactivate tenant. |
| `POST` | `/v1/tenants/{id}/members` | `accessPlatformAdmin` | Directly add a member to any tenant. |
| `POST` | `/v1/identifiers/release` | `accessPlatformAdmin` | Release an identifier from a suspended account. |
| `GET` | `/v1/audit` | `accessPlatformAdmin` | Query platform-wide audit log. |
| `GET` | `/v1/runtimes` | `accessPlatformAdmin` | List configured runtimes from `clients.yaml`. |
| `GET` | `/v1/users` | `accessPlatformAdmin` | List all user accounts platform-wide. |
| `POST` | `/v1/users/{user}/suspend` | `accessPlatformAdmin` | Suspend user, terminate sessions, revoke grants. |
| `POST` | `/v1/users/{user}/activate`| `accessPlatformAdmin` | Reactivate user account. |
| `PUT` | `/v1/users/{user}/platform-admin` | `accessPlatformAdmin` | Grant platform admin role. |
| `DELETE` | `/v1/users/{user}/platform-admin` | `accessPlatformAdmin` | Revoke platform admin role. |

---

## Downstream Verification (Go & TypeScript)

Downstream services should never inspect JWT `sub` directly to authorize actions, as this bypasses agent delegation checks. Use the official verifier libraries in [`verifier/`](../verifier).

### Go Integration

```go
import "t10-auth-server/verifier"

v, err := verifier.New(verifier.Config{
    Issuer:       "http://localhost:8081",
    URL:          "http://auth-server:8081", // Internal cluster URL (optional)
    Service:      "crm-mcp",                 // Expected service audience
    ClientSecret: os.Getenv("SERVICE_SECRET"),
})
if err != nil {
    log.Fatal(err)
}

// In an HTTP middleware:
who, err := v.Verify(r.Context(), bearerToken)
if err != nil {
    http.Error(w, "Unauthorized", http.StatusUnauthorized)
    return
}

// 1. Check if token allows the required action:
if !who.Allows("crm:read") {
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}

// 2. Identify the caller:
userID := who.UserID
tenantID := who.TenantID

if who.IsAgent() {
    // Agent execution details:
    runtime := who.Agent.Runtime
    grantID := who.Agent.GrantID
    trigger := who.Agent.Trigger      // "user", "voice", "schedule", etc.
    constraints := who.Constraints()  // JSON constraint maps
}
```

### TypeScript Integration

Located at [`verifier/ts/verifier.ts`](../verifier/ts/verifier.ts):

```typescript
import { Verifier } from "./verifier.js";

const verifier = new Verifier({
  issuer: process.env.AUTH_PUBLIC_URL!,
  service: "property-service",
  clientSecret: process.env.SERVICE_SECRET,
});

const identity = await verifier.verify(token);

if (!identity.allows("property:resident.read")) {
  throw new ForbiddenError("Missing action permission");
}

console.log(`User ${identity.userId} in tenant ${identity.tenantId}`);
if (identity.isAgent()) {
  console.log(`Executed by ${identity.agent?.runtime} on trigger ${identity.agent?.trigger}`);
}
```

### Verification Semantics

| Token Type | `who.UserID` | `who.ServiceID` | `who.IsAgent()` | `who.Allows(action)` |
|---|---|---|---|---|
| **User Access Token** (`aud: ["t10"]`) | Populated | Empty | `false` | Always `true` (caller checks business policy). |
| **Delegated Agent Token** (`aud: [svc]`) | Populated | Empty | `true` | True only if `action` exists in token and full grant chain. |
| **Service Token** (`aud: ["t10"]`) | Empty | Populated | `false` | Always `false` (service accounts cannot act as users). |

- **Grant Chain Caching**: Chains are cached for **60 seconds**. Revoking a grant takes effect downstream within 60 seconds.
- **Fail-Closed**: If a delegated token's grant chain cannot be fetched from `auth-server`, verification returns `ErrGrantUnavailable` and refuses access.

---

## Operator CLI: authctl

The [`authctl`](../cmd/authctl/main.go) tool runs administrative and operator commands against `DATABASE_URL`.

### Commands Reference

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

# 6. Sample Data (Dev Mode Only)
authctl samples-add          # Seeds test tenants, users, and org units
authctl samples-remove       # Cleans up test fixtures
```

---

## Local Development & Testing

### Running via Docker Compose

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

### Running the Test Suite

```sh
cd auth-server
go test -v ./...
```
Tests run against ephemeral database instances using test containers or local test schemas, covering:
- Route access guard matrix validation ([`verifier_test.go`](../internal/server/verifier_test.go)).
- Session rotation and replay detection.
- Multi-factor authentication & recovery code logic.
- Grant chain validation and depth capping.
- Org tree hierarchy, cycle prevention, and manager placement.
- Business role revisions and catalog parsing.

---

## Troubleshooting & Common Failure Modes

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
