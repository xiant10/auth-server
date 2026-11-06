// Package directory owns tenants, memberships and platform admins.
package directory

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"t10-auth-server/internal/agents"
	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/db"
	"t10-auth-server/internal/ids"
)

// Roles and statuses, mirroring the table constraints.
const (
	RoleMember = "member"
	RoleAdmin  = "admin"

	TenantActive    = "active"
	TenantSuspended = "suspended"

	MemberActive   = "active"
	MemberInactive = "inactive"
)

// Errors returned by the service.
var (
	ErrNotFound       = errors.New("not found")
	ErrExists         = errors.New("already exists")
	ErrInvalid        = errors.New("invalid value")
	ErrTenantDenied   = errors.New("no active membership in that tenant")
	ErrTenantRequired = errors.New("user has several tenants; name one")
	ErrNoTenant       = errors.New("user has no active tenant")
	ErrLastAdmin      = errors.New("a tenant needs at least one active admin")

	ErrInvitationInvalid = errors.New("invitation is invalid, used or expired")
)

// Tenant is one tenant row.
type Tenant struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	// RequireMFA is the tenant's MFA policy.
	RequireMFA bool      `json:"require_mfa"`
	CreatedAt  time.Time `json:"created_at"`
}

// Member is one membership row.
type Member struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
	Role     string `json:"role"`
	Status   string `json:"status"`
}

// Service is the directory module.
type Service struct {
	pool *pgxpool.Pool
}

// NewService builds the module.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// ResolveTenant implements identity.TenantResolver. A platform admin with no
// membership gets an empty tenant, since that role grants none.
func (s *Service) ResolveTenant(ctx context.Context, q db.Querier, userID, requested string) (string, error) {
	if requested != "" {
		if err := checkActive(ctx, q, userID, requested); err != nil {
			return "", err
		}
		return requested, nil
	}
	rows, err := q.Query(ctx,
		`SELECT m.tenant_id FROM auth.memberships m
		 JOIN auth.tenants t ON t.id = m.tenant_id
		 WHERE m.user_id = $1 AND m.status = 'active' AND t.status = 'active'
		 ORDER BY m.tenant_id LIMIT 2`, userID)
	if err != nil {
		return "", fmt.Errorf("list memberships: %w", err)
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return "", fmt.Errorf("list memberships: %w", err)
	}
	switch len(tenants) {
	case 1:
		return tenants[0], nil
	case 0:
		admin, err := isPlatformAdmin(ctx, q, userID)
		if err != nil {
			return "", err
		}
		if admin {
			return "", nil
		}
		return "", ErrNoTenant
	default:
		return "", ErrTenantRequired
	}
}

// CheckActive returns nil only if the user is an active member of an active
// tenant. It fails with ErrTenantDenied otherwise.
func (s *Service) CheckActive(ctx context.Context, userID, tenantID string) error {
	return checkActive(ctx, s.pool, userID, tenantID)
}

func checkActive(ctx context.Context, q db.Querier, userID, tenantID string) error {
	var ok bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM auth.memberships m
			JOIN auth.tenants t ON t.id = m.tenant_id
			JOIN auth.users u ON u.id = m.user_id
			WHERE m.user_id = $1 AND m.tenant_id = $2
			  AND m.status = 'active' AND t.status = 'active' AND u.status = 'active')`,
		userID, tenantID).Scan(&ok)
	if err != nil {
		return fmt.Errorf("check membership: %w", err)
	}
	if !ok {
		return ErrTenantDenied
	}
	return nil
}

// IsPlatformAdmin reports whether the user holds the platform role.
func (s *Service) IsPlatformAdmin(ctx context.Context, userID string) (bool, error) {
	return isPlatformAdmin(ctx, s.pool, userID)
}

func isPlatformAdmin(ctx context.Context, q db.Querier, userID string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM auth.platform_admins WHERE user_id = $1)", userID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check platform admin: %w", err)
	}
	return ok, nil
}

// IsTenantAdmin reports whether the user is an active admin of an active tenant.
func (s *Service) IsTenantAdmin(ctx context.Context, userID, tenantID string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM auth.memberships m
			JOIN auth.tenants t ON t.id = m.tenant_id
			WHERE m.user_id = $1 AND m.tenant_id = $2 AND m.role = 'admin'
			  AND m.status = 'active' AND t.status = 'active')`,
		userID, tenantID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check tenant admin: %w", err)
	}
	return ok, nil
}

// IsPlatformAdminIn implements identity.TenantResolver, for a check that must
// see the caller's transaction.
func (s *Service) IsPlatformAdminIn(ctx context.Context, q db.Querier, userID string) (bool, error) {
	return isPlatformAdmin(ctx, q, userID)
}

// HasPlatformAdmin reports whether bootstrap has already run.
func (s *Service) HasPlatformAdmin(ctx context.Context) (bool, error) {
	var ok bool
	if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM auth.platform_admins)").Scan(&ok); err != nil {
		return false, fmt.Errorf("check platform admins: %w", err)
	}
	return ok, nil
}

// GrantPlatformAdmin gives a user the platform role inside tx.
func (s *Service) GrantPlatformAdmin(ctx context.Context, tx pgx.Tx, actor, userID string) error {
	_, err := tx.Exec(ctx, "INSERT INTO auth.platform_admins (user_id, granted_by) VALUES ($1, $2)", userID, actor)
	if err != nil {
		return translate(err, "grant platform admin")
	}
	return audit.Write(ctx, tx, audit.Entry{
		Actor: actor, Scope: audit.ScopePlatform, Action: "platform_admin.grant", Target: userID, Outcome: audit.Success,
	})
}

// CreateTenant adds a tenant inside tx. An empty id gets a random one.
func (s *Service) CreateTenant(ctx context.Context, tx pgx.Tx, actor, id, name string) (Tenant, error) {
	if name == "" {
		return Tenant{}, fmt.Errorf("%w: tenant name is required", ErrInvalid)
	}
	if id == "" {
		id = ids.New("ten")
	}
	t := Tenant{ID: id, Name: name}
	err := tx.QueryRow(ctx,
		"INSERT INTO auth.tenants (id, name) VALUES ($1, $2) RETURNING status, created_at", id, name).
		Scan(&t.Status, &t.CreatedAt)
	if err != nil {
		return Tenant{}, translate(err, "create tenant")
	}
	err = audit.Write(ctx, tx, audit.Entry{
		Actor: actor, Scope: audit.ScopePlatform, Action: "tenant.create", Target: id, Outcome: audit.Success,
	})
	if err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// Create runs CreateTenant in its own transaction.
func (s *Service) Create(ctx context.Context, actor, id, name string) (Tenant, error) {
	var t Tenant
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		t, err = s.CreateTenant(ctx, tx, actor, id, name)
		return err
	})
	return t, err
}

// GetTenant returns one tenant.
func (s *Service) GetTenant(ctx context.Context, id string) (Tenant, error) {
	t := Tenant{ID: id}
	err := s.pool.QueryRow(ctx,
		"SELECT name, status, require_mfa, created_at FROM auth.tenants WHERE id = $1", id).Scan(&t.Name, &t.Status, &t.RequireMFA, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tenant{}, ErrNotFound
	}
	if err != nil {
		return Tenant{}, fmt.Errorf("get tenant: %w", err)
	}
	return t, nil
}

// TenantSummary is one row of the platform's tenant list.
type TenantSummary struct {
	Tenant
	Members int `json:"members"`
}

// ListTenants returns up to limit tenants whose name or ID contains search.
func (s *Service) ListTenants(ctx context.Context, search string, limit int) ([]TenantSummary, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT t.id, t.name, t.status, t.require_mfa, t.created_at,
		        (SELECT count(*) FROM auth.memberships m WHERE m.tenant_id = t.id AND m.status = 'active')
		 FROM auth.tenants t
		 WHERE position(lower($1) IN lower(t.name)) > 0 OR position(lower($1) IN t.id) > 0
		 ORDER BY t.name, t.id LIMIT $2`, search, limit)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	tenants, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (TenantSummary, error) {
		var t TenantSummary
		err := row.Scan(&t.ID, &t.Name, &t.Status, &t.RequireMFA, &t.CreatedAt, &t.Members)
		return t, err
	})
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	return tenants, nil
}

// SetTenantStatus suspends or reactivates a tenant.
func (s *Service) SetTenantStatus(ctx context.Context, actor, id, status string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE auth.tenants SET status = $2 WHERE id = $1", id, status)
		if err != nil {
			return translate(err, "update tenant")
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopePlatform, Action: "tenant." + status, Target: id, Outcome: audit.Success,
		})
	})
}

// AddMember adds a user to a tenant inside tx.
func (s *Service) AddMember(ctx context.Context, tx pgx.Tx, actor, tenantID, userID, role string) (Member, error) {
	m := Member{ID: ids.New("mem"), TenantID: tenantID, UserID: userID, Role: role, Status: MemberActive}
	_, err := tx.Exec(ctx,
		"INSERT INTO auth.memberships (id, tenant_id, user_id, role) VALUES ($1, $2, $3, $4)",
		m.ID, tenantID, userID, role)
	if err != nil {
		return Member{}, translate(err, "add member")
	}
	err = audit.Write(ctx, tx, audit.Entry{
		Actor: actor, Scope: audit.ScopeTenant(tenantID), Action: "membership.create", Target: userID,
		Outcome: audit.Success, Detail: map[string]any{"role": role},
	})
	if err != nil {
		return Member{}, err
	}
	return m, nil
}

// Add runs AddMember in its own transaction.
func (s *Service) Add(ctx context.Context, actor, tenantID, userID, role string) (Member, error) {
	var m Member
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		m, err = s.AddMember(ctx, tx, actor, tenantID, userID, role)
		return err
	})
	return m, err
}

// ListMembers returns a tenant's memberships.
func (s *Service) ListMembers(ctx context.Context, tenantID string) ([]Member, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, tenant_id, user_id, role, status FROM auth.memberships
		 WHERE tenant_id = $1 ORDER BY created_at, id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	members, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Member])
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	return members, nil
}

// MemberDetail is a membership with the sign-in name an admin knows the user by.
type MemberDetail struct {
	Member
	Name string `json:"name"`
	// UserStatus is the account's own status, set by a platform admin.
	UserStatus string    `json:"user_status"`
	JoinedAt   time.Time `json:"joined_at"`
	// ManagerUserID and UnitID are empty when unset, and the two names are for
	// display.
	ManagerUserID string `json:"manager_user_id,omitempty"`
	ManagerName   string `json:"manager_name,omitempty"`
	UnitID        string `json:"org_unit_id,omitempty"`
	UnitName      string `json:"org_unit_name,omitempty"`
}

// ListMemberDetails returns a tenant's memberships for the admin UI.
func (s *Service) ListMemberDetails(ctx context.Context, tenantID string) ([]MemberDetail, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT m.id, m.tenant_id, m.user_id, m.role, m.status, m.created_at,
		        COALESCE((SELECT i.value FROM auth.user_identifiers i
		                  WHERE i.user_id = m.user_id ORDER BY i.created_at, i.value LIMIT 1), ''),
		        mu.status, COALESCE(boss.user_id, ''),
		        COALESCE((SELECT i.value FROM auth.user_identifiers i
		                  WHERE i.user_id = boss.user_id ORDER BY i.created_at, i.value LIMIT 1), ''),
		        COALESCE(m.org_unit_id, ''), COALESCE(u.name, '')
		 FROM auth.memberships m
		 JOIN auth.users mu ON mu.id = m.user_id
		 LEFT JOIN auth.memberships boss ON boss.tenant_id = m.tenant_id AND boss.id = m.manager_id
		 LEFT JOIN auth.org_units u ON u.tenant_id = m.tenant_id AND u.id = m.org_unit_id
		 WHERE m.tenant_id = $1 ORDER BY m.status, m.role, m.created_at, m.id LIMIT 500`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	members, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (MemberDetail, error) {
		var m MemberDetail
		err := row.Scan(&m.ID, &m.TenantID, &m.UserID, &m.Role, &m.Status, &m.JoinedAt, &m.Name,
			&m.UserStatus, &m.ManagerUserID, &m.ManagerName, &m.UnitID, &m.UnitName)
		return m, err
	})
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	return members, nil
}

// MemberUpdate changes a membership. Nil fields stay as they are.
type MemberUpdate struct {
	Role   *string
	Status *string
}

// UpdateMember changes a member's role or status. It refuses to leave a tenant
// with no active admin, which only a platform admin could then repair.
func (s *Service) UpdateMember(ctx context.Context, actor, tenantID, userID string, u MemberUpdate) (Member, error) {
	var m Member
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Locking the tenant serializes two admins demoting each other. A role or
		// status change alters what the member may do, so it raises the revision
		// entitlement reads return.
		if _, err := tx.Exec(ctx,
			"UPDATE auth.tenants SET authorization_revision = authorization_revision + 1 WHERE id = $1", tenantID); err != nil {
			return fmt.Errorf("lock tenant: %w", err)
		}
		var wasAdmin bool
		err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM auth.memberships
			                WHERE tenant_id = $1 AND user_id = $2 AND role = 'admin' AND status = 'active')`,
			tenantID, userID).Scan(&wasAdmin)
		if err != nil {
			return fmt.Errorf("check member: %w", err)
		}
		err = tx.QueryRow(ctx,
			`UPDATE auth.memberships
			 SET role = COALESCE($3, role), status = COALESCE($4, status)
			 WHERE tenant_id = $1 AND user_id = $2
			 RETURNING id, tenant_id, user_id, role, status`,
			tenantID, userID, u.Role, u.Status).Scan(&m.ID, &m.TenantID, &m.UserID, &m.Role, &m.Status)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return translate(err, "update member")
		}
		if m.Status != MemberActive {
			if err := agents.RevokeMemberGrants(ctx, tx, userID, tenantID); err != nil {
				return err
			}
		}
		if wasAdmin {
			var remaining int
			err := tx.QueryRow(ctx,
				// A suspended admin can't sign in, so they don't count as cover.
				`SELECT count(*) FROM auth.memberships m JOIN auth.users u ON u.id = m.user_id
				 WHERE m.tenant_id = $1 AND m.role = 'admin' AND m.status = 'active' AND u.status = 'active'`,
				tenantID).Scan(&remaining)
			if err != nil {
				return fmt.Errorf("count admins: %w", err)
			}
			if remaining == 0 {
				return ErrLastAdmin
			}
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopeTenant(tenantID), Action: "membership.update", Target: userID,
			Outcome: audit.Success, Detail: map[string]any{"role": m.Role, "status": m.Status},
		})
	})
	if err != nil {
		return Member{}, err
	}
	return m, nil
}

// IsTenantRequired implements identity.TenantResolver.
func (s *Service) IsTenantRequired(err error) bool {
	return errors.Is(err, ErrTenantRequired)
}

// UserTenant is one of a user's active tenants.
type UserTenant struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
	// RequireMFA is for the tenant picker, which says so before someone picks it.
	RequireMFA bool `json:"-"`
}

// ListUserTenants returns the tenants a user can select.
func (s *Service) ListUserTenants(ctx context.Context, userID string) ([]UserTenant, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT t.id, t.name, m.role, t.require_mfa FROM auth.memberships m
		 JOIN auth.tenants t ON t.id = m.tenant_id
		 WHERE m.user_id = $1 AND m.status = 'active' AND t.status = 'active'
		 ORDER BY t.name, t.id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowToStructByPos[UserTenant])
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	return tenants, nil
}

// TenantRequiresMFA implements identity.TenantResolver.
func (s *Service) TenantRequiresMFA(ctx context.Context, q db.Querier, tenantID string) (bool, error) {
	var required bool
	err := q.QueryRow(ctx, "SELECT require_mfa FROM auth.tenants WHERE id = $1", tenantID).Scan(&required)
	if err != nil {
		return false, fmt.Errorf("check tenant MFA: %w", err)
	}
	return required, nil
}

// MFAMandatory implements identity.TenantResolver: a platform admin, or an
// active member of a tenant that requires it, must keep a second factor.
func (s *Service) MFAMandatory(ctx context.Context, userID string) (bool, error) {
	var mandatory bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM auth.platform_admins WHERE user_id = $1)
		     OR EXISTS (SELECT 1 FROM auth.memberships m JOIN auth.tenants t ON t.id = m.tenant_id
		                WHERE m.user_id = $1 AND m.status = 'active' AND t.require_mfa)`, userID).Scan(&mandatory)
	if err != nil {
		return false, fmt.Errorf("check mandatory MFA: %w", err)
	}
	return mandatory, nil
}

// SetRequireMFA changes a tenant's MFA policy.
func (s *Service) SetRequireMFA(ctx context.Context, actor, tenantID string, required bool) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE auth.tenants SET require_mfa = $2 WHERE id = $1", tenantID, required)
		if err != nil {
			return translate(err, "update tenant")
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopeTenant(tenantID), Action: "tenant.require_mfa", Target: tenantID,
			Outcome: audit.Success, Detail: map[string]any{"required": required},
		})
	})
}

// CanTenantAdminReset reports whether a tenant admin may issue a reset link for
// a user. An account spans tenants, so a reset reaches everything it holds. A
// tenant admin may therefore only reset a plain member whose account lives
// wholly in that tenant; anyone else needs a platform admin.
func (s *Service) CanTenantAdminReset(ctx context.Context, tenantID, userID string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM auth.memberships
		                WHERE tenant_id = $1 AND user_id = $2 AND role = 'member')
		    AND NOT EXISTS (SELECT 1 FROM auth.memberships
		                    WHERE user_id = $2 AND tenant_id <> $1)
		    AND NOT EXISTS (SELECT 1 FROM auth.platform_admins WHERE user_id = $2)`,
		tenantID, userID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check reset eligibility: %w", err)
	}
	return ok, nil
}

// IsMember reports whether the user has any membership row in the tenant.
func (s *Service) IsMember(ctx context.Context, tenantID, userID string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM auth.memberships WHERE tenant_id = $1 AND user_id = $2)", tenantID, userID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check membership: %w", err)
	}
	return ok, nil
}

const invitationTTL = 7 * 24 * time.Hour

func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// CreateInvitation returns a single-use link token that expires in 7 days.
func (s *Service) CreateInvitation(ctx context.Context, actor, tenantID, role string) (string, error) {
	b := make([]byte, 32)
	rand.Read(b) // Never fails; see crypto/rand.
	token := base64.RawURLEncoding.EncodeToString(b)
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			"INSERT INTO auth.invitations (token_hash, tenant_id, role, created_by, expires_at) VALUES ($1, $2, $3, $4, $5)",
			hashToken(token), tenantID, role, actor, time.Now().Add(invitationTTL))
		if err != nil {
			return translate(err, "create invitation")
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopeTenant(tenantID), Action: "invitation.create", Target: tenantID,
			Outcome: audit.Success, Detail: map[string]any{"role": role},
		})
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// AcceptInvitation spends a token and adds the user inside tx. It is never
// matched to a sign-in name, since those prove nothing.
func (s *Service) AcceptInvitation(ctx context.Context, tx pgx.Tx, actor, token, userID string) (Member, error) {
	var tenantID, role string
	err := tx.QueryRow(ctx,
		`UPDATE auth.invitations i SET accepted_at = now()
		 FROM auth.tenants t
		 WHERE t.id = i.tenant_id AND t.status = 'active'
		   AND i.token_hash = $1 AND i.accepted_at IS NULL AND i.expires_at > now()
		 RETURNING i.tenant_id, i.role`, hashToken(token)).Scan(&tenantID, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		return Member{}, ErrInvitationInvalid
	}
	if err != nil {
		return Member{}, fmt.Errorf("spend invitation: %w", err)
	}
	return s.AddMember(ctx, tx, actor, tenantID, userID, role)
}

// translate maps constraint failures to the service's errors.
func translate(err error, what string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return ErrExists
		case "23503":
			return ErrNotFound
		case "23514":
			return ErrInvalid
		}
	}
	return fmt.Errorf("%s: %w", what, err)
}
