# Mobile API guide

How the t10 mobile app integrates with the auth service. [openapi.yaml](openapi.yaml) has every field. This guide covers what the spec cannot: keys, signing, and which call comes when.

Use client ID `t10-mobile`. No other client may call `/v1/login`.

## Keys

Create two P-256 keys in the Secure Enclave or Android Keystore when the app first needs them. The private keys never leave the device.

| Key | Unlock | Used for |
| --- | --- | --- |
| Session key | None, works silently | Enrolling, and refreshing tokens |
| Approval key | Biometrics or device passcode, on every use | Approving sign-ins, and sensitive account changes |

Send public keys as base64url, in either SPKI DER (Android's `getEncoded()`) or uncompressed X9.63 (iOS's `SecKeyCopyExternalRepresentation`). A generated key pair is one device: keep it across sign-outs. Generate new ones only after `device_revoked`.

## Signing

1. Call `POST /v1/challenges` with the purpose. A challenge lasts 2 minutes and works once, for that purpose only.
2. Build the message below, with `\n` line feeds and no trailing newline.
3. Sign it with ECDSA over SHA-256. Pass the message itself, and let the platform hash it: `ecdsaSignatureMessageX962SHA256` on iOS, `SHA256withECDSA` on Android. Both produce the ASN.1 DER form this API expects.
4. Send the signature as base64url.

```text
t10-device-v1
<purpose>
<challenge>
<binding>
```

| Operation | Purpose | Key | Binding |
| --- | --- | --- | --- |
| Login | `login` | Session | Key binding |
| Register | `register` | Session | Key binding |
| Start pairing | `pair` | Session | Key binding |
| Refresh | `refresh` | Session | The `session_id` |
| Approve a QR request | `approve` | Approval | The QR ID |
| Account change | `reauth` | Approval | `<device_id>`, a line feed, then the action |

**Key binding** is the lowercase hex SHA-256 of the session public key as an uncompressed point (65 bytes, starting `04`), whichever encoding you send. On Android, take the last 65 bytes of the SPKI form.

**Actions** are `password`, `name_add`, `name_remove`, `totp_start`, `totp_disable`, `recovery_codes` and `device_revoke:<device_id>`.

## Signing in

```text
POST /v1/challenges {purpose: login}
POST /v1/login      {client_id, name, password, device, challenge, signature}
```

| Result | Next step |
| --- | --- |
| `status: ok` | Store `session_id` and `device_id`. Keep `access_token` in memory |
| `status: mfa_required` | Ask for the TOTP code, then `POST /v1/login/mfa` with `mfa_token`. It allows 5 tries in 5 minutes |
| `device_approval_required` | This account already has a device. Start [pairing](#adding-a-second-device) |
| `device_revoked` | These keys were removed. Generate new ones and try again |
| `invalid_credentials` | Show one message. Never suggest which part was wrong |

Calling `/v1/login` again with the same keys returns to the same device, with no approval needed. Do this after any session ends.

Registration is the same with `purpose: register` and `POST /v1/login/register`. Show the returned `recovery_codes` once. Outside dev mode it needs an `invite`, or fails with `registration_closed`. If the invitation's tenant requires a second factor, `tenant` comes back empty: turn on TOTP with `/v1/me/totp/*`, then refresh to enter the tenant.

## Staying signed in

Access tokens last 5 minutes, so refresh when under 60 seconds remain, and only while the app is in use. A background refresh would keep an abandoned session alive forever.

```text
POST /v1/challenges {purpose: refresh}
POST /v1/token      grant_type=device_refresh&client_id=t10-mobile&session_id=...&challenge=...&signature=...
```

This call is form-encoded. Nothing rotates, so after a network failure get a new challenge and retry. Each refresh extends the 90-day idle limit, and there is no absolute limit.

On `invalid_grant`, the session ended: return to sign-in with the same keys. On `tenant_denied`, the user lost that tenant: call `/v1/me`, and pick another with a refresh.

## Tenants

If a user has several tenants and none was named, `tenant` comes back empty and the token cannot reach anything tenant-scoped. Read `tenants` from `GET /v1/me`, let the user pick, and refresh with `tenant=<id>`. The choice stays on the session. Use the same refresh to switch later.

## Approving a QR code

The camera path for a sign-in on another device:

1. Scan the code. It is a URL ending `/v1/qr/<id>`. **Refuse it unless its origin is your auth server.**
2. `POST /v1/qr/<id>/claim` with the bearer token.
3. Show `client_name`, `requester_ip`, `user_agent` and, for `kind: device`, `device_name`. Attackers can show victims their own code, so this screen is the defense. Make the user confirm.
4. On yes, sign with the approval key and call `/approve`, which prompts for biometrics. On no, call `/deny`.

The server gives no location yet, because it has no GeoIP database. See [Known limits](#known-limits).

## Adding a second device

1. On the new device, `POST /v1/login/pair`, signed with purpose `pair`.
2. Show `qr_payload` as a QR code, and keep `poll_token` secret.
3. On the enrolled device, approve it as above.
4. On the new device, `POST /v1/login/pair/poll` about every 2 seconds. An approval returns tokens, once.

A user with TOTP can skip this: `/v1/login` plus the code enrolls a new device directly.

## Account changes

The routes under `/v1/me`, and device removal, need a device session. Those marked with a proof action in the spec need a fresh signature from the approval key, so the OS prompts for biometrics. This replaces the current password: an enrolled app resets a password this way.

Show "Sign out" as `POST /v1/logout`. It ends the session and leaves the device enrolled.

**Lost phone:** the user signs in on the web with their password or a recovery code, and removes the device at `/v1/account`. Its sessions and approval rights end at once.

## MFA policies

A device counts as a second factor only if one was proved when it enrolled: a TOTP code, or approval by a device that itself counts. A device enrolled with only a password does not. Otherwise, anyone with the password could enroll a phone and pass an MFA policy with it.

A user caught by this gets `mfa_required`. They need to turn on TOTP, then enroll a fresh device.

## Rate limits

Limits return `429 rate_limited`, per IP and per account, and are shared with the web pages. Back off and tell the user to wait.

Five wrong passwords or codes lock an account for 30 seconds, doubling up to an hour. During a lock, right credentials also return `invalid_credentials`.

## Known limits

- **No attestation.** The server cannot tell a real phone from a script holding software keys, and cannot see that a key really needs biometrics. Adding App Attest and Play Integrity needs its own decision.
- **No location.** Claim returns IP and user agent, not a place.
- **No push.** Approval starts from a scan, by design for v1.
