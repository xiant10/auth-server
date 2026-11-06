# Security review brief

For the external reviewers of rollout step 4. Public registration stays closed until this review is finished and its findings are resolved. Outside dev mode, accounts can only be created by invitation.

[design.md](design.md) is the intended system, and this page lists where the code differs from it. [mobile-api.md](mobile-api.md) and [openapi.yaml](openapi.yaml) are the mobile contract.

## Scope

**In scope:** everything in this repo, about 8,000 lines of Go plus SQL migrations, and the verifier libraries.

| Area | Where |
| --- | --- |
| Passwords, lockout, limits, sign-in names | `internal/identity/password.go`, `service.go`, `limits.go`, `names.go` |
| TOTP and recovery | `internal/identity/mfa.go`, `recovery.go` |
| Code flow, refresh rotation, JWTs, keys | `internal/identity/oauth.go`, `tokens.go`, `keys.go` |
| Device keys, app login, QR approval | `internal/identity/device.go`, `mobile.go`, `qr.go` |
| Tenants, invitations, reset rights | `internal/directory/service.go` |
| Room admission and LiveKit tokens | `internal/agents/admission.go` |
| Agent grants, runtime limits, service accounts | `internal/agents/grants.go`, `runtimes.go`, `internal/identity/service_accounts.go` |
| Org tree, managers, `/v1/org` reads and tenant admin writes | `internal/directory/org.go`, `internal/server/org.go` |
| User suspension and the platform role | `internal/identity/account.go`, `internal/directory/users.go` |
| Token verifiers for other services | `verifier/verifier.go`, `verifier/ts/verifier.ts` |
| Routes, access rules, pages, headers | `internal/server/` |
| Admin JSON routes for workbench and the console, and the `/admin` redirect | `internal/server/admin.go`, `handlers.go`, `org.go` |
| Audit log and schema | `internal/audit/`, `internal/db/migrations/` |
| Client list, config checks, container | `clients.yaml`, `internal/config/`, `Dockerfile` |

The Mac client's loopback PKCE flow (`t10-mac-client/internal/room/oauth.go`) is in scope as the first consumer of the code flow. So are the two grant consumers: `t10-livekit-agent/internal/authclient` and `agent-pi/packages/agent-pi/src/auth/grants.ts`.

**Out of scope, because they don't exist yet:** the mobile app, the business microservices, and production infrastructure. No production environment has been chosen, so the ingress, secret store, failover database and TLS to Postgres can't be assessed.

## Run it

`docker compose up --build` starts a seeded dev stack on `:8081`. Dev mode adds the password grant, open registration and waived platform MFA, and config refuses it unless the public URL is localhost. To test production behavior, set `AUTH_DEV_MODE=false`, an https `AUTH_PUBLIC_URL`, and real keys from `authctl gen-key` and `authctl gen-totp-key`.

Tests are described in the [README](../README.md#test). `internal/server/review_test.go` holds the regressions for the findings below.

## Where to look hardest

1. **Device trust.** The server can't tell a Secure Enclave key from a software key, and only the app enforces the biometric check behind the approval key. Is key possession an acceptable second factor without attestation? See `mfa_capable` in `mobile.go`.
2. **Recovery with no verified contact.** One recovery code resets the password on an account without TOTP, even if it has an MFA-capable device. Two recovery codes remove TOTP.
3. **QR phishing.** A code an attacker relays to a victim signs the attacker in if the victim approves. The approval screen shows the requester's IP and user agent, and the device name on a pairing request. The user agent and device name come from the attacker.
4. **Refresh grace.** The previous refresh secret stays valid until the new one is first used, so a lost response can't sign anyone out. Check that this can't be used to keep a stolen session alive unnoticed.
5. **Silent code flow.** With a live browser session, `/v1/authorize` issues a code with no consent screen, to any loopback port for the Mac client. A local process that wins the port race can receive it, but it still needs the PKCE verifier from whoever began the flow, so this should only help an attacker who starts the flow themselves.
6. **Tenant admin reset links.** They are limited to plain members whose account belongs to that tenant alone. An admin can then sign in as a member who has no TOTP, including one whose only second factor is a device.
7. **Isolation.** `tid` handling, `<tenant>__<room>` naming, which adds the user for `conv-` rooms and refuses `__` in a requested name, and every `accessTenantAdmin` handler.
8. **Agent grants.** Can anything mint a token beyond its chain? Check `liveChain`, `checkRuntime`, and the rule that a listed service may renew a grant it doesn't run. `VerifyDelegated` skips the audience on purpose, and `mayUse` decides instead. Model output must never reach `POST /v1/grants`.
9. **Org reads.** Any active service account can read any tenant's org data by naming the tenant. That follows the design's single trust zone, but it means one compromised service can list every tenant's reporting lines.
10. **Admin UI.** It runs on the browser cookie, so `guardAdmin` repeats what a token would prove: the tenant in the URL, the tenant's MFA policy, and a second factor from the last 15 minutes for platform actions. It relies on the Origin check and `SameSite=Lax` against cross-site posts. Tenant admins now see each member's first sign-in name, which may be a phone number or email the user gave for another purpose. The only script is a nonce-allowed Copy button on the pages that show an invitation or reset link. The language switch posts to `/v1/language`, which needs no session, under the same Origin check. Its `next` goes through `safeNext`, plus the signed-out pages. The form carries a reset or invitation page's address, token included, back to that page. The switch never appears beside a secret shown once. Its cookie holds only a language.
11. **Platform role.** Any platform admin can make another, and the only check is a second factor in the last 15 minutes, so one stolen admin session can add a lasting admin. Each change is audited, but nothing alerts anyone. The new admin needs their own authenticator before they can act. Check the row locks that keep two admins from removing each other, and a suspension and a role grant from both succeeding.
12. **Platform access to a tenant.** A platform admin can use any tenant's admin routes, reset any member and join any tenant, which is deliberate. The control is detection, not prevention: `auditPlatformAccess` records it in the tenant's audit log and refuses the request if it can't. Reads collapse to one row per admin an hour, and a platform admin who has joined a tenant then looks like any member, apart from the `membership.create` row. Nothing alerts the tenant, who only sees this by opening Activity. Is that enough?

## Pre-review results

This was an internal check, written by the same author as the code, so it doesn't replace the external review. It read all non-test code, compared each claim in the design's Security considerations with the code, and ran `govulncheck`, `staticcheck` and `gosec`. Each finding was reproduced by a failing test first. Severities are the author's.

### Fixed

| Severity | Finding | Fix |
| --- | --- | --- |
| High | **Connection pool deadlock.** Refresh, code redemption and app login held a transaction while the tenant check asked the pool for a second connection. A burst of ordinary traffic could hang sign-in for everyone | Tenant checks read through the open transaction, and every request has a 20-second deadline |
| High | **Lockout skipped by held MFA tokens.** `/v1/login/mfa` never checked lockout, so a stolen password could collect tokens and try a TOTP code about 100 times instead of 5 | Lockout now stops tokens already issued |
| Medium | **No recency check on platform actions.** The design requires a second factor within 15 minutes, but any session that ever proved one passed, for as long as it kept refreshing | Platform actions need a factor proved within 15 minutes |
| Medium | **Timing revealed accounts in recovery.** Unknown names ran a dummy hash and real names did not, so unknown names took about 8 times longer | Neither path hashes on a wrong code |
| Medium | **Per-account limit bypass.** The limit counted the name as typed, so respelling a phone number restarted it. This also affected recovery, including its TOTP guesses | The limit counts the stored form |
| Medium | **Per-IP limit bypass over IPv6.** Each address counted separately, so one /64 could rotate past every limit | IPv6 is counted by /64 |
| Medium | **Lost recovery codes.** An app signup invited into an MFA-required tenant created the account, then failed with `mfa_required`, so its recovery codes were never shown | The signup gets a session with no tenant, and can enroll a factor |
| Medium | **No HSTS** on any response | Set on all https responses |
| Medium | **Example LiveKit secret accepted in production** | Config refuses it outside dev mode |
| Low | **A suspended user could finish a login** in progress and get a 5-minute token | Status is rechecked when the session is created |
| Low | **QR pairing and sign-in were interchangeable.** A pairing's poll token could collect a browser session, which also destroyed the pairing | Polls must match the request's kind |
| Low | **Approval by a device revoked before collection** returned a 500 | Reports `expired`, and no session is created |
| Low | **Old reset links survived** a password change | Unused links are cancelled |
| Low | **A session kept its MFA flag** after TOTP was turned off | Cleared for browser and client sessions |
| Low | **Password length counted bytes,** so six Chinese characters passed a 10-character rule | Counts characters |
| Low | **Internal-error logs held the path,** including QR IDs | Logs the route pattern |
| Low | **An account with no name crashed** TOTP setup after a name release | Uses a fallback label |
| Bug | **The authenticator link was blank,** because `html/template` strips `otpauth:` URLs | Marked safe, built only by the OTP library |
| Dependency | **GO-2026-6809,** a `crypto/x509` issue fixed in Go 1.27.3 | Toolchain and Docker image pinned to 1.27.3 |

### Scanner results that need no change

| Tool | Result | Why |
| --- | --- | --- |
| `gosec` G124 | Cookie `Secure` not constant | It follows the https check, and config requires https outside dev mode |
| `gosec` G710 | Open redirect, twice | `safeNext` allows three local paths, and `AllowsRedirect` checks the client list. Both are tested |
| `gosec` G304 | File path from a variable | It is the operator's `AUTH_CLIENTS_FILE` |
| `gosec` G104 | Unhandled `fs.Parse` | Those flag sets exit on error |
| `gosec` G203 | Unescaped template URL | This is the authenticator link above |
| `govulncheck` | GO-2026-5932, `x/crypto/openpgp` | The package is never imported |

### Open

**These block public registration:**

| Gap | Design says | Current state |
| --- | --- | --- |
| Password blocklist | Common and known-breached passwords | About 60 hand-written entries |
| CAPTCHA | On web and mobile from day one | None, and the choice is still open for China-based users |
| New-tenant quotas | Low limits on agent runs and model spend | None, and the numbers are undecided |

**These need a decision or a production environment:**

| Gap | Risk |
| --- | --- |
| Audit log protection | The design says the app role has no `UPDATE` or `DELETE`. In fact the app role owns the table and runs migrations, so triggers block those statements but it could drop the triggers. Fixing this needs a separate migration role |
| Second-factor lockout | Someone who lost their authenticator and has fewer than two recovery codes has no way back |
| No attestation | See "Where to look hardest" |
| No location on QR approval | The design calls for approximate location, but there is no GeoIP data |
| No security alerts | With no verified contact, nobody is told about a new device or a password change |
| Targeted lockout | Anyone can keep an account locked out of password sign-in by repeatedly failing it. Each lock lasts at most an hour, and QR sign-in still works |
| TOTP key rotation | `AUTH_TOTP_KEY` has no rotation path |
| Revocation delay | A stopped grant's existing tokens last up to 5 minutes, or 1 minute at a service using the verifier, because of its chain cache. agent-pi and the voice agent keep using a token they hold until it nears expiry |
| Voice call length | A voice grant can't be extended, so a call past 8 hours loses agent access until the user rejoins |
| Old voice children | Rejoining makes a new child grant in agent-pi, and the old one stays valid until it expires, though nothing uses it |
| Service secrets | Failed `client_secret` attempts aren't rate limited. Secrets hold 256 random bits and each attempt is one indexed read |
| Suspension delay | A suspended user's API tokens stop at once on this server. Other services accept them until they expire, up to 5 minutes later, and a LiveKit room token already issued can open a connection for up to 10 minutes |
| Service-token audit | Grant creation, extension and revocation are audited, but successful exchanges and org reads aren't, because of their volume |
| Audit detail | Rows don't record the client IP |
| Ingress assumptions | `AUTH_TRUST_PROXY` assumes exactly one proxy, which appends the client address. Reset and invitation tokens travel in query strings, so ingress logs must not keep them. [deployment.md](deployment.md) lists what the ingress must do |
| Hashing inside transactions | Registration and password changes run Argon2 while holding a connection. Limits and the request deadline bound this, but a load test should confirm it |

## Differences from the design

- Outside dev mode, registration needs an invitation, on the web and in the API.
- A tenant admin can reset only a plain member whose account belongs to that tenant alone.
- Adding a member by ID is platform-admin only. Tenants use invitations.
- A device counts as MFA only if a factor was proved when it enrolled.
- There is no "password, then app" step in place of TOTP. QR sign-in covers that case.
- A login with several tenants returns a token with no `tid`, until a refresh picks one. So does an app signup to a tenant that requires a factor, until one is enrolled.
- MFA for platform admins is enforced when they act, not when the account is created.
- Platform admins re-sign in through the normal sign-in page.
- Removing or demoting a tenant's last active admin is refused, in the API and the UI.
- A password change also stops the user's agent grants, not just a reset, because it's how people respond to a stolen password.
- `/v1/org` reads name their tenant in the query, because a service token has none.
- Grant audiences must fit the runtime's list as well as the parent, and `audiences` narrow like actions do.
- Disabling a service stops every grant in a chain that runs through it.
- `GET /v1/grants/{id}/chain` refuses a stopped grant rather than returning it, which closes the revocation window at services that use the verifier.
- A platform admin can't be suspended until another platform admin removes the role, which also means the last one can't be suspended.
- Org reads leave out suspended users, and a suspended admin doesn't count towards a tenant's last active admin. A tenant whose only admin is suspended has nobody to run it until a platform admin steps in.
