package directory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/ids"
)

// Kinds of account.
const (
	KindPerson = "person"
	KindAgent  = "agent"
)

const maxAgentName = 100

// AgentAccount is what a tenant admin sets when creating a tenant agent
// account, such as an agent teammate. Its manager and unit are optional.
type AgentAccount struct {
	DisplayName   string `json:"display_name"`
	ManagerUserID string `json:"manager_user_id"`
	OrgUnitID     string `json:"org_unit_id"`
}

func cleanAgentName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxAgentName {
		return "", ErrInvalid
	}
	return name, nil
}

// CreateAgentAccount adds a tenant agent account: a user of kind agent with no
// sign-in, an active membership with role member in this tenant only, and its
// place in the org. It never holds a token: only grants rooted in it do. The
// migration's triggers keep it without a sign-in, in one tenant, and nobody's
// manager.
func (s *Service) CreateAgentAccount(ctx context.Context, actor, tenantID string, a AgentAccount) (OrgMember, error) {
	name, err := cleanAgentName(a.DisplayName)
	if err != nil {
		return OrgMember{}, err
	}
	userID := ids.New("acc")
	err = s.orgTx(ctx, tenantID, func(tx pgx.Tx) error {
		var active bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM auth.tenants WHERE id = $1 AND status = 'active')", tenantID).Scan(&active); err != nil {
			return fmt.Errorf("read tenant: %w", err)
		}
		if !active {
			return ErrNotFound
		}
		if _, err := tx.Exec(ctx, "INSERT INTO auth.users (id, kind, display_name) VALUES ($1, 'agent', $2)", userID, name); err != nil {
			return translate(err, "create agent account")
		}
		if _, err := s.AddMember(ctx, tx, actor, tenantID, userID, RoleMember); err != nil {
			return err
		}
		if err := place(ctx, tx, actor, tenantID, Placement{UserID: userID, ManagerUserID: a.ManagerUserID, OrgUnitID: a.OrgUnitID}); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopeTenant(tenantID), Action: "agent_account.create", Target: userID,
			Outcome: audit.Success, Detail: map[string]any{"name": name, "manager": a.ManagerUserID, "unit": a.OrgUnitID},
		})
	})
	if err != nil {
		return OrgMember{}, err
	}
	return s.OrgMember(ctx, tenantID, userID)
}

// RenameAgentAccount changes an agent account's display name. A person's name
// is their own to change, so this refuses anyone but an agent account.
func (s *Service) RenameAgentAccount(ctx context.Context, actor, tenantID, userID, displayName string) (OrgMember, error) {
	name, err := cleanAgentName(displayName)
	if err != nil {
		return OrgMember{}, err
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE auth.users u SET display_name = $3
			 FROM auth.memberships m
			 WHERE u.id = $2 AND u.kind = 'agent' AND m.user_id = u.id AND m.tenant_id = $1`,
			tenantID, userID, name)
		if err != nil {
			return fmt.Errorf("rename agent account: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopeTenant(tenantID), Action: "agent_account.rename", Target: userID,
			Outcome: audit.Success, Detail: map[string]any{"name": name},
		})
	})
	if err != nil {
		return OrgMember{}, err
	}
	return s.OrgMember(ctx, tenantID, userID)
}

// AgentAccountIn reports whether userID is an active agent account of the
// tenant, for consent that only such an account may be given.
func (s *Service) AgentAccountIn(ctx context.Context, tenantID, userID string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM auth.memberships m JOIN auth.users u ON u.id = m.user_id
		                WHERE m.tenant_id = $1 AND m.user_id = $2 AND u.kind = 'agent'
		                  AND m.status = 'active' AND u.status = 'active')`, tenantID, userID).Scan(&ok)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, fmt.Errorf("read agent account: %w", err)
	}
	return ok, nil
}

// ManagedAgents returns the active agent accounts whose nearest active manager
// is userID, so a service can let a teammate's manager approve its actions or
// read its runs with the manager's own token.
func (s *Service) ManagedAgents(ctx context.Context, tenantID, userID string) ([]string, error) {
	reports, err := s.Reports(ctx, tenantID, userID, false)
	if errors.Is(err, ErrNotFound) {
		return []string{}, nil
	}
	if err != nil || len(reports) == 0 {
		return []string{}, err
	}
	rows, err := s.pool.Query(ctx, "SELECT id FROM auth.users WHERE id = ANY($1) AND kind = 'agent' ORDER BY id", reports)
	if err != nil {
		return nil, fmt.Errorf("read agent reports: %w", err)
	}
	return collectIDs(rows)
}
