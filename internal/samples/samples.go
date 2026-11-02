// Package samples creates throwaway accounts for local testing and removes them
// again. They share a published password, so the commands that call this refuse
// to run outside dev mode.
package samples

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/identity"
)

const (
	// Password is shared by every sample account.
	Password = "t10-sample-password"

	actor = "authctl:samples"

	// TenantAcme and TenantGlobex are the sample tenants.
	TenantAcme   = "ten_sample-acme"
	TenantGlobex = "ten_sample-globex"
)

// ErrExists means the samples are already there.
var ErrExists = errors.New("sample accounts already exist")

// Account is one sample account.
type Account struct {
	Name     string
	Platform bool
	// Tenants maps tenant ID to role.
	Tenants map[string]string
	// Inactive makes the memberships inactive.
	Inactive bool
	Tests    string
}

// Accounts are the sample accounts, one for each kind of user.
var Accounts = []Account{
	{Name: "sample-platform", Platform: true, Tests: "platform admin, in no tenant"},
	{Name: "sample-acme-admin", Tenants: map[string]string{TenantAcme: directory.RoleAdmin}, Tests: "tenant admin of Sample Acme"},
	{Name: "sample-globex-admin", Tenants: map[string]string{TenantGlobex: directory.RoleAdmin}, Tests: "tenant admin of Sample Globex; cannot see Acme"},
	{Name: "sample-member", Tenants: map[string]string{TenantAcme: directory.RoleMember}, Tests: "plain member; no admin access"},
	{Name: "sample-multi", Tenants: map[string]string{TenantAcme: directory.RoleMember, TenantGlobex: directory.RoleMember}, Tests: "member of both; only a platform admin can reset"},
	{Name: "sample-inactive", Tenants: map[string]string{TenantAcme: directory.RoleMember}, Inactive: true, Tests: "inactive member; refused a tenant token"},
}

var tenants = []struct{ id, name string }{
	{TenantAcme, "Sample Acme"},
	{TenantGlobex, "Sample Globex"},
}

// Add creates the sample tenants and accounts, all or nothing.
func Add(ctx context.Context, pool *pgxpool.Pool, ids *identity.Service, dir *directory.Service) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var exists bool
		err := tx.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM auth.users WHERE sample) OR EXISTS (SELECT 1 FROM auth.tenants WHERE id = ANY($1))",
			[]string{TenantAcme, TenantGlobex}).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check samples: %w", err)
		}
		if exists {
			return ErrExists
		}
		for _, t := range tenants {
			if _, err := dir.CreateTenant(ctx, tx, actor, t.id, t.name); err != nil {
				return err
			}
		}
		for _, a := range Accounts {
			userID, err := ids.CreateUser(ctx, tx, actor, identity.NewUser{Name: a.Name, Password: Password, DisplayName: a.Name})
			if err != nil {
				return fmt.Errorf("%s: %w", a.Name, err)
			}
			// The flag, not a name, marks a sample, so removal cannot reach a real
			// account that merely has a similar name.
			if _, err := tx.Exec(ctx, "UPDATE auth.users SET sample = true WHERE id = $1", userID); err != nil {
				return fmt.Errorf("mark %s: %w", a.Name, err)
			}
			if a.Platform {
				if err := dir.GrantPlatformAdmin(ctx, tx, actor, userID); err != nil {
					return err
				}
			}
			for tenant, role := range a.Tenants {
				if _, err := dir.AddMember(ctx, tx, actor, tenant, userID, role); err != nil {
					return err
				}
			}
			if a.Inactive {
				if _, err := tx.Exec(ctx, "UPDATE auth.memberships SET status = 'inactive' WHERE user_id = $1", userID); err != nil {
					return fmt.Errorf("deactivate %s: %w", a.Name, err)
				}
			}
			if _, err := ids.IssueRecoveryCodes(ctx, tx, userID); err != nil {
				return err
			}
		}
		return nil
	})
}

// Removed counts what Remove deleted.
type Removed struct {
	Users, Tenants int
}

// Remove deletes every sample account and tenant, with whatever they gathered
// during testing: sessions, devices, QR requests and invitations. A real user
// who joined a sample tenant loses only that membership. Audit rows stay,
// because the log is append-only.
func Remove(ctx context.Context, pool *pgxpool.Pool) (Removed, error) {
	var removed Removed
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT id FROM auth.users WHERE sample")
		if err != nil {
			return fmt.Errorf("find samples: %w", err)
		}
		users, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return fmt.Errorf("find samples: %w", err)
		}
		tenantIDs := []string{TenantAcme, TenantGlobex}

		// Children first, because these foreign keys have no cascade.
		for _, stmt := range []struct {
			sql  string
			args []any
		}{
			{`DELETE FROM auth.auth_codes WHERE session_id IN (SELECT id FROM auth.sessions WHERE user_id = ANY($1))
			     OR issued_session_id IN (SELECT id FROM auth.sessions WHERE user_id = ANY($1))`, []any{users}},
			{"DELETE FROM auth.qr_logins WHERE user_id = ANY($1)", []any{users}},
			{"DELETE FROM auth.mfa_challenges WHERE user_id = ANY($1)", []any{users}},
			{"DELETE FROM auth.sessions WHERE user_id = ANY($1)", []any{users}},
			{"DELETE FROM auth.devices WHERE user_id = ANY($1)", []any{users}},
			{"DELETE FROM auth.platform_admins WHERE user_id = ANY($1)", []any{users}},
			{"DELETE FROM auth.agent_grants WHERE user_id = ANY($1) OR tenant_id = ANY($2)", []any{users, tenantIDs}},
			{`UPDATE auth.memberships SET manager_id = NULL, org_unit_id = NULL WHERE tenant_id = ANY($2)
			     OR manager_id IN (SELECT id FROM auth.memberships WHERE user_id = ANY($1))`, []any{users, tenantIDs}},
			{"DELETE FROM auth.org_units WHERE tenant_id = ANY($1)", []any{tenantIDs}},
			{"DELETE FROM auth.memberships WHERE user_id = ANY($1) OR tenant_id = ANY($2)", []any{users, tenantIDs}},
			{"DELETE FROM auth.invitations WHERE tenant_id = ANY($1)", []any{tenantIDs}},
			{"UPDATE auth.sessions SET active_tenant_id = NULL WHERE active_tenant_id = ANY($1)", []any{tenantIDs}},
		} {
			if _, err := tx.Exec(ctx, stmt.sql, stmt.args...); err != nil {
				return fmt.Errorf("clear sample data: %w", err)
			}
		}
		tag, err := tx.Exec(ctx, "DELETE FROM auth.users WHERE id = ANY($1)", users)
		if err != nil {
			return fmt.Errorf("delete sample users: %w", err)
		}
		removed.Users = int(tag.RowsAffected())
		if tag, err = tx.Exec(ctx, "DELETE FROM auth.tenants WHERE id = ANY($1)", tenantIDs); err != nil {
			return fmt.Errorf("delete sample tenants: %w", err)
		}
		removed.Tenants = int(tag.RowsAffected())
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopePlatform, Action: "samples.remove", Outcome: audit.Success,
			Detail: map[string]any{"users": removed.Users, "tenants": removed.Tenants},
		})
	})
	return removed, err
}
