# Consumer identity plan

Nov 2, 2026 · Deferred. Not scheduled, and nothing here is designed yet

Holds what consumer agent apps would need, kept apart from the agent plane designs so that work doesn't wait on it. It belongs to `auth-server`, because most of it is identity. The agent plane fits consumer apps with almost no change. Identity, cost and abuse controls don't yet.

## Starting direction

Keep one platform, and add a small consumer identity and plans layer rather than a separate stack. One person is one personal tenant, as `auth-server`'s dev mode already does, so tenant isolation, quota and session ownership keep working with no new concept.

## Gaps to design

| Gap | Today | Consumer needs |
| --- | --- | --- |
| Sign-up | Invite-only outside dev mode, waiting on the security review and a CAPTCHA | Open registration with abuse protection |
| Sign-in | Password plus TOTP, unverified names, no social login | Apple, Google or WeChat, and phone verification |
| Plans and billing | None | Free tier and app-store subscriptions |
| Abuse and safety | Card redaction and injection marking only | Content moderation, per-user rate limits, age rules |
| Long-term memory | Per session. No memory layer seen, not checked in depth | Memory across conversations |
| Capacity | No load test, and replicas can't be removed | Real numbers, and a way to retire replicas |

## Depends on

These belong to the agent plane's enterprise prerequisites, so they should be done there first:

- Durable quota, per user as well as per tenant.
- An account deletion and retention path across harnesses.
- `auth-server`'s external security review, before open sign-up.

## Notes for later

- Plans could reuse the `entitlements` table in `t10-agent-control` ([`governance.md`](../../t10-agent-control/docs/governance.md)), and routes could send free users to a cheaper pool or model.
- One process per conversation is too costly at this scale, so a harness with `sessions: many` is the realistic choice.
- Voice is the largest cost risk, so free users should get limited or no calls.
