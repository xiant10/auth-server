# Test users and account maintenance

Sample accounts for local testing, and how each kind of user is created and managed. The samples are temporary and only work in dev mode.

## Sample accounts

Tenant admins sign in to workbench and open Administration. Platform admins sign in to the platform console. <http://localhost:8081/admin> sends each to the right one. All six accounts use the password `t10-sample-password`.

| Sign-in name | Role | What it tests |
| --- | --- | --- |
| `sample-platform` | Platform admin, in no tenant | Every tenant and all platform actions |
| `sample-acme-admin` | Tenant admin of Sample Acme | Managing Acme only. The all-tenants page is refused |
| `sample-globex-admin` | Tenant admin of Sample Globex | Tenant isolation. Acme's page is refused |
| `sample-member` | Member of Sample Acme | No admin access |
| `sample-multi` | Member of both tenants | Picking a tenant at sign-in. Only a platform admin can reset this account |
| `sample-inactive` | Inactive member of Sample Acme | No admin access, and a tenant token is refused |

The tenants are `ten_sample-acme` (Sample Acme) and `ten_sample-globex` (Sample Globex).

The local stack also seeds `ada@acme.example` with the password `change-me-enterprise-admin`. It's a platform admin and the admin of `ten_acme`, and it isn't one of the samples, so removal leaves it alone.

## Agents and the organization

As `sample-acme-admin`, open Sample Acme. **Organization** builds the unit tree, and each member's row on **Members** sets their manager and unit. **Agents** lists every call and agent run, with a Stop button. It fills up when someone joins a room while the local stack lists a voice runtime in `clients.yaml`.

As `sample-platform`, open **Users** to find anyone by sign-in name or full user ID, suspend or reactivate them, and add or remove the platform role. A suspended account shows a badge on its tenant's **Members** tab.

## Add and remove

With the local stack running:

```sh
docker compose exec auth-server authctl samples-add
docker compose exec auth-server authctl samples-remove
```

Removal deletes the sample accounts, both sample tenants, and what they gathered during testing, such as sessions, devices and invitations.

- A real user who joined a sample tenant loses only that membership.
- An account is treated as a sample by a hidden marker, not its name, so `sample-lookalike` would survive.
- Audit rows stay, because the log is append-only.
- Both commands refuse to run outside dev mode, because the password is published.
- `docker compose down -v` also removes them, along with the rest of the local database.

## How each kind of user is maintained

| User | Created by | Managed by |
| --- | --- | --- |
| Platform admin | `authctl bootstrap` for the first one, then any platform admin from **Users** | Their own account page. They must have an authenticator, and platform actions need a sign-in with it in the last 15 minutes. Another platform admin can remove the role, but the last one can't lose it |
| Tenant admin | An admin invitation, promotion by another admin of that tenant, or a platform admin adding them by user ID. Anyone who self-registers also runs their own new tenant, but outside dev mode registration needs an invitation | Other admins of that tenant, or a platform admin. The last active admin can't be removed |
| Member | An invitation link, or `authctl add-user` | Their tenant's admins set role and active or inactive status. A platform admin can suspend the account from **Users**, which applies in every tenant |

**Reset links:** a tenant admin can only reset a plain member who belongs to that tenant alone. Everyone else needs a platform admin.

## Not built yet

- **Deleting real users or tenants:** only the samples can be deleted. Real users and tenants can be suspended.
- **Removing a lost authenticator:** this is still an open decision in the design.
