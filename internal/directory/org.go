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

// Kinds of org unit.
const (
	UnitDepartment = "department"
	UnitTeam       = "team"
)

const maxUnitName = 100

// Org errors.
var (
	// ErrCycle means a change would make someone their own manager, or a unit
	// its own ancestor.
	ErrCycle = errors.New("that would create a cycle")
	// ErrUnitInUse means a unit still has members or child units.
	ErrUnitInUse = errors.New("unit is in use")
)

// Unit is one org unit. Depth and Members are filled by ListUnits.
type Unit struct {
	ID       string `json:"id"`
	ParentID string `json:"parent_id,omitempty"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Depth    int    `json:"-"`
	Members  int    `json:"-"`
}

// OrgMember is one member's place in the organization.
type OrgMember struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	Status string `json:"status"`
	// UserStatus is the account's own status, which a suspension changes in
	// every tenant at once.
	UserStatus string `json:"user_status"`
	// ManagerUserID is the nearest active manager up the chain, so someone
	// leaving doesn't cut off the people under them.
	ManagerUserID string `json:"manager_user_id,omitempty"`
	// AssignedManagerUserID is the link as an admin set it, which can name
	// someone who left. It's kept so that reinstating them restores the chain.
	AssignedManagerUserID string `json:"assigned_manager_user_id,omitempty"`
	OrgUnitID             string `json:"org_unit_id,omitempty"`
	DisplayName           string `json:"display_name"`
}

// orgMemberColumns reads an OrgMember from auth.memberships m and auth.users u.
const orgMemberColumns = `m.user_id, m.role, m.status, u.status,
	COALESCE((WITH RECURSIVE up AS (
		SELECT b.id, b.user_id, b.status, b.manager_id, 1 AS depth FROM auth.memberships b
		WHERE b.tenant_id = m.tenant_id AND b.id = m.manager_id
		UNION ALL
		SELECT b.id, b.user_id, b.status, b.manager_id, up.depth + 1 FROM auth.memberships b
		JOIN up ON b.tenant_id = m.tenant_id AND b.id = up.manager_id
	)
	SELECT up.user_id FROM up JOIN auth.users bu ON bu.id = up.user_id
	WHERE up.status = 'active' AND bu.status = 'active' ORDER BY up.depth LIMIT 1), ''),
	COALESCE((SELECT b.user_id FROM auth.memberships b WHERE b.tenant_id = m.tenant_id AND b.id = m.manager_id), ''),
	COALESCE(m.org_unit_id, ''), u.display_name`

func (m *OrgMember) scan(row pgx.Row) error {
	return row.Scan(&m.UserID, &m.Role, &m.Status, &m.UserStatus, &m.ManagerUserID, &m.AssignedManagerUserID, &m.OrgUnitID, &m.DisplayName)
}

// MaxMemberPage is the most members one OrgMembers call returns.
const MaxMemberPage = 500

// MemberQuery narrows and pages OrgMembers. Empty fields don't filter.
type MemberQuery struct {
	// Search matches display names only. Sign-in names are unverified and can
	// hold a phone number, so teammates must not be able to find people by them.
	Search string
	UnitID string
	// ActiveOnly leaves out members whose membership or account isn't active.
	// A sweep leaves it false: someone missing from a page isn't someone who left.
	ActiveOnly bool
	After      string
	Limit      int
}

// OrgMembers returns one page of a tenant's members, in user ID order, and the
// cursor of the next page, which is empty on the last one.
func (s *Service) OrgMembers(ctx context.Context, tenantID string, q MemberQuery) ([]OrgMember, string, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM auth.tenants WHERE id = $1)", tenantID).Scan(&exists); err != nil {
		return nil, "", fmt.Errorf("read tenant: %w", err)
	}
	if !exists {
		return nil, "", ErrNotFound
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+orgMemberColumns+`
		 FROM auth.memberships m JOIN auth.users u ON u.id = m.user_id
		 WHERE m.tenant_id = $1 AND m.user_id > $2
		   AND ($3 = '' OR u.display_name ILIKE '%' || $3 || '%')
		   AND ($4 = '' OR m.org_unit_id = $4)
		   AND (NOT $5 OR (m.status = 'active' AND u.status = 'active'))
		 ORDER BY m.user_id LIMIT $6`,
		tenantID, q.After, likePattern.Replace(q.Search), q.UnitID, q.ActiveOnly, q.Limit+1)
	if err != nil {
		return nil, "", fmt.Errorf("list org members: %w", err)
	}
	members, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (OrgMember, error) {
		var m OrgMember
		return m, m.scan(row)
	})
	if err != nil {
		return nil, "", fmt.Errorf("list org members: %w", err)
	}
	if len(members) > q.Limit {
		members = members[:q.Limit]
		return members, members[q.Limit-1].UserID, nil
	}
	return members, "", nil
}

// likePattern makes a search term literal inside ILIKE.
var likePattern = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// orgTx runs fn holding the tenant's org lock, so that two concurrent edits
// can't each pass the cycle check and create a cycle together.
func (s *Service) orgTx(ctx context.Context, tenantID string, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 42))", tenantID); err != nil {
			return fmt.Errorf("lock org: %w", err)
		}
		return fn(tx)
	})
}

func cleanUnit(name, kind string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxUnitName || (kind != UnitDepartment && kind != UnitTeam) {
		return "", ErrInvalid
	}
	return name, nil
}

func nullable(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// CreateUnit adds a unit, under parentID if it isn't empty.
func (s *Service) CreateUnit(ctx context.Context, actor, tenantID, name, kind, parentID string) (Unit, error) {
	name, err := cleanUnit(name, kind)
	if err != nil {
		return Unit{}, err
	}
	u := Unit{ID: ids.New("org"), ParentID: parentID, Name: name, Kind: kind}
	err = s.orgTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			"INSERT INTO auth.org_units (id, tenant_id, parent_id, name, kind) VALUES ($1, $2, $3, $4, $5)",
			u.ID, tenantID, nullable(parentID), name, kind)
		if err != nil {
			return translate(err, "create unit")
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopeTenant(tenantID), Action: "org_unit.create", Target: u.ID, Outcome: audit.Success,
			Detail: map[string]any{"name": name, "kind": kind, "parent": parentID},
		})
	})
	if err != nil {
		return Unit{}, err
	}
	return u, nil
}

// UpdateUnit renames a unit or moves it to another parent.
func (s *Service) UpdateUnit(ctx context.Context, actor, tenantID, id, name, kind, parentID string) error {
	name, err := cleanUnit(name, kind)
	if err != nil {
		return err
	}
	return s.orgTx(ctx, tenantID, func(tx pgx.Tx) error {
		if parentID != "" {
			var cycle bool
			err := tx.QueryRow(ctx,
				`WITH RECURSIVE up AS (
					SELECT id, parent_id FROM auth.org_units WHERE tenant_id = $1 AND id = $2
					UNION
					SELECT u.id, u.parent_id FROM auth.org_units u JOIN up ON u.tenant_id = $1 AND u.id = up.parent_id
				)
				SELECT EXISTS (SELECT 1 FROM up WHERE id = $3)`, tenantID, parentID, id).Scan(&cycle)
			if err != nil {
				return fmt.Errorf("check unit cycle: %w", err)
			}
			if cycle {
				return ErrCycle
			}
		}
		tag, err := tx.Exec(ctx,
			"UPDATE auth.org_units SET name = $3, kind = $4, parent_id = $5 WHERE tenant_id = $1 AND id = $2",
			tenantID, id, name, kind, nullable(parentID))
		if err != nil {
			return translate(err, "update unit")
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopeTenant(tenantID), Action: "org_unit.update", Target: id, Outcome: audit.Success,
			Detail: map[string]any{"name": name, "kind": kind, "parent": parentID},
		})
	})
}

// DeleteUnit removes an empty unit. It refuses one with members or children,
// because moving them is a choice only the admin can make.
func (s *Service) DeleteUnit(ctx context.Context, actor, tenantID, id string) error {
	return s.orgTx(ctx, tenantID, func(tx pgx.Tx) error {
		var inUse bool
		err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM auth.org_units WHERE tenant_id = $1 AND parent_id = $2)
			     OR EXISTS (SELECT 1 FROM auth.memberships WHERE tenant_id = $1 AND org_unit_id = $2)`, tenantID, id).Scan(&inUse)
		if err != nil {
			return fmt.Errorf("check unit: %w", err)
		}
		if inUse {
			return ErrUnitInUse
		}
		tag, err := tx.Exec(ctx, "DELETE FROM auth.org_units WHERE tenant_id = $1 AND id = $2", tenantID, id)
		if err != nil {
			return fmt.Errorf("delete unit: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopeTenant(tenantID), Action: "org_unit.delete", Target: id, Outcome: audit.Success,
		})
	})
}

// ListUnits returns a tenant's units as a tree, each parent before its children.
func (s *Service) ListUnits(ctx context.Context, tenantID string) ([]Unit, error) {
	rows, err := s.pool.Query(ctx,
		`WITH RECURSIVE tree AS (
			SELECT id, parent_id, name, kind, 0 AS depth, ARRAY[lower(name), id] AS path
			FROM auth.org_units WHERE tenant_id = $1 AND parent_id IS NULL
			UNION ALL
			SELECT u.id, u.parent_id, u.name, u.kind, t.depth + 1, t.path || ARRAY[lower(u.name), u.id]
			FROM auth.org_units u JOIN tree t ON u.tenant_id = $1 AND u.parent_id = t.id
		)
		SELECT t.id, COALESCE(t.parent_id, ''), t.name, t.kind, t.depth,
		       (SELECT count(*) FROM auth.memberships m JOIN auth.users mu ON mu.id = m.user_id
		        WHERE m.tenant_id = $1 AND m.org_unit_id = t.id AND m.status = 'active' AND mu.status = 'active')
		FROM tree t ORDER BY t.path`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list units: %w", err)
	}
	units, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Unit, error) {
		var u Unit
		err := row.Scan(&u.ID, &u.ParentID, &u.Name, &u.Kind, &u.Depth, &u.Members)
		return u, err
	})
	if err != nil {
		return nil, fmt.Errorf("list units: %w", err)
	}
	return units, nil
}

// SetPlacement sets a member's manager and unit, both by the user ID or unit ID,
// and both optional. Tokens carry neither, so this needs no revocation.
func (s *Service) SetPlacement(ctx context.Context, actor, tenantID, userID, managerUserID, unitID string) error {
	return s.orgTx(ctx, tenantID, func(tx pgx.Tx) error {
		var memberID string
		err := tx.QueryRow(ctx, "SELECT id FROM auth.memberships WHERE tenant_id = $1 AND user_id = $2", tenantID, userID).Scan(&memberID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read member: %w", err)
		}
		// An unchanged manager needs no check. They may have left since it was
		// set, and refusing would make every unit change also cut the chain.
		var managerID *string
		err = tx.QueryRow(ctx,
			`SELECT b.id FROM auth.memberships m JOIN auth.memberships b ON b.tenant_id = m.tenant_id AND b.id = m.manager_id
			 WHERE m.tenant_id = $1 AND m.id = $2 AND b.user_id = $3`, tenantID, memberID, managerUserID).Scan(&managerID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("read current manager: %w", err)
		}
		if managerID == nil && managerUserID != "" {
			id, err := managerMembership(ctx, tx, tenantID, memberID, managerUserID)
			if err != nil {
				return err
			}
			managerID = &id
		}
		_, err = tx.Exec(ctx, "UPDATE auth.memberships SET manager_id = $3, org_unit_id = $4 WHERE tenant_id = $1 AND id = $2",
			tenantID, memberID, managerID, nullable(unitID))
		if err != nil {
			return translate(err, "update placement")
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopeTenant(tenantID), Action: "membership.placement", Target: userID, Outcome: audit.Success,
			Detail: map[string]any{"manager": managerUserID, "unit": unitID},
		})
	})
}

// managerMembership finds an active manager and refuses a loop: walking up from
// the new manager must never reach the member.
func managerMembership(ctx context.Context, tx pgx.Tx, tenantID, memberID, managerUserID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx,
		`SELECT m.id FROM auth.memberships m JOIN auth.users u ON u.id = m.user_id
		 WHERE m.tenant_id = $1 AND m.user_id = $2 AND m.status = 'active' AND u.status = 'active'`,
		tenantID, managerUserID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInvalid
	}
	if err != nil {
		return "", fmt.Errorf("read manager: %w", err)
	}
	var cycle bool
	err = tx.QueryRow(ctx,
		`WITH RECURSIVE up AS (
			SELECT id, manager_id FROM auth.memberships WHERE tenant_id = $1 AND id = $2
			UNION
			SELECT m.id, m.manager_id FROM auth.memberships m JOIN up ON m.tenant_id = $1 AND m.id = up.manager_id
		)
		SELECT EXISTS (SELECT 1 FROM up WHERE id = $3)`, tenantID, id, memberID).Scan(&cycle)
	if err != nil {
		return "", fmt.Errorf("check manager cycle: %w", err)
	}
	if cycle {
		return "", ErrCycle
	}
	return id, nil
}

// OrgMember returns one member's place in the organization.
func (s *Service) OrgMember(ctx context.Context, tenantID, userID string) (OrgMember, error) {
	var m OrgMember
	err := m.scan(s.pool.QueryRow(ctx,
		`SELECT `+orgMemberColumns+`
		 FROM auth.memberships m JOIN auth.users u ON u.id = m.user_id
		 WHERE m.tenant_id = $1 AND m.user_id = $2`, tenantID, userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return OrgMember{}, ErrNotFound
	}
	if err != nil {
		return OrgMember{}, fmt.Errorf("read org member: %w", err)
	}
	return m, nil
}

// Reports returns the user IDs of a manager's active reports, for a module to
// filter on before pagination. Both reads walk through inactive or suspended
// managers, so someone leaving doesn't hide the people under them: a direct read
// finds everyone whose nearest active manager is this user.
func (s *Service) Reports(ctx context.Context, tenantID, userID string, transitive bool) ([]string, error) {
	if _, err := s.OrgMember(ctx, tenantID, userID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx,
		`WITH RECURSIVE reports AS (
			SELECT m.id, m.user_id, m.status = 'active' AND u.status = 'active' AS active FROM auth.memberships m
			JOIN auth.users u ON u.id = m.user_id
			JOIN auth.memberships boss ON boss.tenant_id = m.tenant_id AND boss.id = m.manager_id
			WHERE m.tenant_id = $1 AND boss.user_id = $2
			UNION
			SELECT m.id, m.user_id, m.status = 'active' AND u.status = 'active' FROM auth.memberships m
			JOIN auth.users u ON u.id = m.user_id
			JOIN reports r ON m.tenant_id = $1 AND m.manager_id = r.id
			WHERE $3 OR NOT r.active
		)
		SELECT user_id FROM reports WHERE active ORDER BY user_id`, tenantID, userID, transitive)
	if err != nil {
		return nil, fmt.Errorf("list reports: %w", err)
	}
	return collectIDs(rows)
}

// UnitMembers returns the user IDs of a unit's active members, and with
// transitive those of the units beneath it.
func (s *Service) UnitMembers(ctx context.Context, tenantID, unitID string, transitive bool) ([]string, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM auth.org_units WHERE tenant_id = $1 AND id = $2)", tenantID, unitID).Scan(&exists)
	if err != nil {
		return nil, fmt.Errorf("read unit: %w", err)
	}
	if !exists {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx,
		`WITH RECURSIVE units AS (
			SELECT id FROM auth.org_units WHERE tenant_id = $1 AND id = $2
			UNION
			SELECT u.id FROM auth.org_units u JOIN units ON u.tenant_id = $1 AND u.parent_id = units.id WHERE $3
		)
		SELECT m.user_id FROM auth.memberships m JOIN auth.users mu ON mu.id = m.user_id
		WHERE m.tenant_id = $1 AND m.status = 'active' AND mu.status = 'active' AND m.org_unit_id IN (SELECT id FROM units)
		ORDER BY m.user_id`, tenantID, unitID, transitive)
	if err != nil {
		return nil, fmt.Errorf("list unit members: %w", err)
	}
	return collectIDs(rows)
}

func collectIDs(rows pgx.Rows) ([]string, error) {
	// CollectRows gives an empty list, never nil, so JSON callers don't see null.
	userIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("read user ids: %w", err)
	}
	return userIDs, nil
}
