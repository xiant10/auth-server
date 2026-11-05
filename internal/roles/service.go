package roles

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/db"
	"t10-auth-server/internal/ids"
)

const (
	maxNameLength        = 100
	maxDescriptionLength = 500
	// MaxEntitlementUsers is the most users one entitlement read answers for,
	// enough for a page of records with their people.
	MaxEntitlementUsers = 200
)

// Errors returned by the service.
var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
	ErrInvalid  = errors.New("invalid value")
	// ErrStale means the caller's revision is out of date: someone else changed
	// it first.
	ErrStale = errors.New("revision is out of date")
	// ErrUnknownPermission names a permission this deployment can't add to a
	// role: not declared, deprecated, retired or from a module not deployed.
	ErrUnknownPermission = errors.New("permission can't be added")
	ErrRoleDisabled      = errors.New("role is disabled")
	// ErrUnknownModule means the module isn't in this deployment's catalog.
	ErrUnknownModule = errors.New("module isn't deployed here")
	// ErrNotModuleService means a service asked for a namespace it doesn't own.
	ErrNotModuleService = errors.New("service may not read that module")
	// ErrDeployed refuses to purge a module that is still in the catalog.
	ErrDeployed = errors.New("module is still deployed")
)

// syncLock serializes replicas writing the catalog at startup.
const syncLock = 7410_0008

// Service is the roles module.
type Service struct {
	pool    *pgxpool.Pool
	catalog *Catalog
}

// NewService builds the module over this deployment's catalog.
func NewService(pool *pgxpool.Pool, catalog *Catalog) *Service {
	return &Service{pool: pool, catalog: catalog}
}

// Catalog is this deployment's catalog.
func (s *Service) Catalog() *Catalog { return s.catalog }

// Sync records the catalog's permissions, so roles can refer to them. It never
// removes one: a module left out of this deployment keeps its rows, and its
// permissions confer nothing until it returns.
func (s *Service) Sync(ctx context.Context) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", syncLock); err != nil {
			return fmt.Errorf("lock permission catalog: %w", err)
		}
		for _, m := range s.catalog.modules {
			for _, p := range m.Permissions {
				_, err := tx.Exec(ctx,
					`INSERT INTO auth.permission_definitions (key, module, description, version, lifecycle)
					 VALUES ($1, $2, $3, $4, $5)
					 ON CONFLICT (key) DO UPDATE
					 SET module = EXCLUDED.module, description = EXCLUDED.description,
					     version = EXCLUDED.version, lifecycle = EXCLUDED.lifecycle, updated_at = now()
					 WHERE (permission_definitions.module, permission_definitions.description,
					        permission_definitions.version, permission_definitions.lifecycle)
					       IS DISTINCT FROM (EXCLUDED.module, EXCLUDED.description, EXCLUDED.version, EXCLUDED.lifecycle)`,
					p.Key, m.ID, p.Description, m.Version, p.Lifecycle)
				if err != nil {
					return fmt.Errorf("record permission %s: %w", p.Key, err)
				}
			}
		}
		return nil
	})
}

// Unavailable is a permission a tenant's roles hold that confers nothing here,
// because its module isn't deployed or it has been retired.
type Unavailable struct {
	Key         string `json:"key"`
	Module      string `json:"module"`
	Description string `json:"description"`
	Reason      string `json:"reason"`
}

// CatalogView is what a tenant admin's role editor offers.
type CatalogView struct {
	Modules     []Module      `json:"modules"`
	Unavailable []Unavailable `json:"unavailable"`
}

// CatalogFor returns the deployed modules, and the permissions this tenant's
// roles hold that no longer confer anything, so the editor can show them.
func (s *Service) CatalogFor(ctx context.Context, tenantID string) (CatalogView, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT d.key, d.module, d.description, d.lifecycle
		 FROM auth.role_permissions rp JOIN auth.permission_definitions d ON d.key = rp.permission
		 WHERE rp.tenant_id = $1 ORDER BY d.key`, tenantID)
	if err != nil {
		return CatalogView{}, fmt.Errorf("list role permissions: %w", err)
	}
	held, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Unavailable, error) {
		var u Unavailable
		var lifecycle string
		err := row.Scan(&u.Key, &u.Module, &u.Description, &lifecycle)
		return u, err
	})
	if err != nil {
		return CatalogView{}, fmt.Errorf("list role permissions: %w", err)
	}
	view := CatalogView{Modules: s.catalog.Modules(), Unavailable: []Unavailable{}}
	for _, u := range held {
		if s.catalog.Grants(u.Key) {
			continue
		}
		u.Reason = s.unavailableReason(u.Key)
		view.Unavailable = append(view.Unavailable, u)
	}
	return view, nil
}

func (s *Service) unavailableReason(key string) string {
	if _, ok := s.catalog.byKey[key]; ok {
		return "retired"
	}
	return "module_not_deployed"
}

// TemplateRef is where a role came from.
type TemplateRef struct {
	Module  string `json:"module"`
	ID      string `json:"id"`
	Version int    `json:"version"`
	// LatestVersion is the deployed module's catalog version, when newer than
	// the one the role was made from. Nothing changes the role by itself.
	LatestVersion int `json:"latest_version,omitempty"`
}

// Role is one tenant role.
type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
	Revision    int64    `json:"revision"`
	Permissions []string `json:"permissions"`
	// Unavailable are the permissions that confer nothing in this deployment.
	Unavailable []string `json:"unavailable"`
	// Active is false for a disabled role, or one with no permission that
	// confers anything here.
	Active      bool         `json:"active"`
	Template    *TemplateRef `json:"template,omitempty"`
	Assignments int          `json:"assignments"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

const roleColumns = `r.id, r.name, r.description, r.enabled, r.revision, r.template_module, r.template_id,
	r.template_version, r.created_at, r.updated_at,
	COALESCE((SELECT array_agg(rp.permission ORDER BY rp.permission) FROM auth.role_permissions rp
	          WHERE rp.tenant_id = r.tenant_id AND rp.role_id = r.id), '{}'),
	(SELECT count(*) FROM auth.member_role_assignments a
	 JOIN auth.memberships m ON m.tenant_id = a.tenant_id AND m.id = a.membership_id
	 WHERE a.tenant_id = r.tenant_id AND a.role_id = r.id AND a.status = 'active' AND m.status = 'active')`

func (s *Service) scanRole(row pgx.Row) (Role, error) {
	var r Role
	var module, template string
	var version int
	err := row.Scan(&r.ID, &r.Name, &r.Description, &r.Enabled, &r.Revision, &module, &template, &version,
		&r.CreatedAt, &r.UpdatedAt, &r.Permissions, &r.Assignments)
	if err != nil {
		return Role{}, err
	}
	s.describe(&r, module, template, version)
	return r, nil
}

// describe fills what depends on this deployment's catalog.
func (s *Service) describe(r *Role, module, template string, version int) {
	r.Unavailable = []string{}
	usable := false
	for _, key := range r.Permissions {
		if s.catalog.Grants(key) {
			usable = true
		} else {
			r.Unavailable = append(r.Unavailable, key)
		}
	}
	r.Active = r.Enabled && usable
	if module != "" {
		r.Template = &TemplateRef{Module: module, ID: template, Version: version}
		if m, ok := s.catalog.Module(module); ok && m.Version > version {
			r.Template.LatestVersion = m.Version
		}
	}
}

// ListRoles returns a tenant's roles, by name.
func (s *Service) ListRoles(ctx context.Context, tenantID string) ([]Role, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+roleColumns+` FROM auth.tenant_roles r WHERE r.tenant_id = $1 ORDER BY lower(r.name), r.id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	roles, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Role, error) { return s.scanRole(row) })
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	return roles, nil
}

// GetRole returns one role.
func (s *Service) GetRole(ctx context.Context, tenantID, roleID string) (Role, error) {
	return s.getRole(ctx, s.pool, tenantID, roleID)
}

func (s *Service) getRole(ctx context.Context, q db.Querier, tenantID, roleID string) (Role, error) {
	r, err := s.scanRole(q.QueryRow(ctx,
		`SELECT `+roleColumns+` FROM auth.tenant_roles r WHERE r.tenant_id = $1 AND r.id = $2`, tenantID, roleID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Role{}, ErrNotFound
	}
	if err != nil {
		return Role{}, fmt.Errorf("get role: %w", err)
	}
	return r, nil
}

// NewRole is a role to create. With Template set, its name, description and
// permissions default to the template's.
type NewRole struct {
	Name        string
	Description string
	Permissions []string
	// TemplateModule and TemplateID name a deployed module's template.
	TemplateModule, TemplateID string
}

// CreateRole adds a role. Every permission must be one this deployment offers.
func (s *Service) CreateRole(ctx context.Context, actor, tenantID string, n NewRole) (Role, error) {
	var module, template string
	var version int
	if n.TemplateModule != "" || n.TemplateID != "" {
		m, t, ok := s.catalog.template(n.TemplateModule, n.TemplateID)
		if !ok {
			return Role{}, fmt.Errorf("%w: no template %s/%s here", ErrInvalid, n.TemplateModule, n.TemplateID)
		}
		module, template, version = m.ID, t.ID, m.Version
		if n.Name == "" {
			n.Name = t.Name
		}
		if n.Description == "" {
			n.Description = t.Description
		}
		if n.Permissions == nil {
			n.Permissions = t.Permissions
		}
	}
	name, err := cleanText(n.Name, n.Description)
	if err != nil {
		return Role{}, err
	}
	keys, err := s.newPermissions(nil, n.Permissions)
	if err != nil {
		return Role{}, err
	}
	var role Role
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := bumpRevision(ctx, tx, tenantID); err != nil {
			return err
		}
		id := ids.New("rol")
		_, err := tx.Exec(ctx,
			`INSERT INTO auth.tenant_roles (id, tenant_id, name, description, template_module, template_id, template_version)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			id, tenantID, name, strings.TrimSpace(n.Description), module, template, version)
		if err != nil {
			return translate(err, "create role")
		}
		if err := setPermissions(ctx, tx, tenantID, id, keys); err != nil {
			return err
		}
		if role, err = s.getRole(ctx, tx, tenantID, id); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopeTenant(tenantID), Action: "role.create", Target: id, Outcome: audit.Success,
			Detail: map[string]any{"name": role.Name, "permissions": role.Permissions, "template": role.Template},
		})
	})
	if err != nil {
		return Role{}, err
	}
	return role, nil
}

// RoleUpdate changes a role. Revision must be the one the caller read; nil
// fields stay. Permissions, when set, replace the whole list.
type RoleUpdate struct {
	Revision    int64
	Name        *string
	Description *string
	Enabled     *bool
	Permissions []string
}

// UpdateRole edits a role. A permission the role already holds may stay even if
// its module is gone, so editing a role never forces a purge; any new one must
// be on offer here.
func (s *Service) UpdateRole(ctx context.Context, actor, tenantID, roleID string, u RoleUpdate) (Role, error) {
	var role Role
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := bumpRevision(ctx, tx, tenantID); err != nil {
			return err
		}
		before, err := s.getRole(ctx, tx, tenantID, roleID)
		if err != nil {
			return err
		}
		if before.Revision != u.Revision {
			return ErrStale
		}
		name, description := before.Name, before.Description
		if u.Name != nil {
			name = *u.Name
		}
		if u.Description != nil {
			description = *u.Description
		}
		if name, err = cleanText(name, description); err != nil {
			return err
		}
		enabled := before.Enabled
		if u.Enabled != nil {
			enabled = *u.Enabled
		}
		_, err = tx.Exec(ctx,
			`UPDATE auth.tenant_roles SET name = $3, description = $4, enabled = $5, revision = revision + 1, updated_at = now()
			 WHERE tenant_id = $1 AND id = $2`,
			tenantID, roleID, name, strings.TrimSpace(description), enabled)
		if err != nil {
			return translate(err, "update role")
		}
		if u.Permissions != nil {
			keys, err := s.newPermissions(before.Permissions, u.Permissions)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "DELETE FROM auth.role_permissions WHERE tenant_id = $1 AND role_id = $2", tenantID, roleID); err != nil {
				return fmt.Errorf("clear role permissions: %w", err)
			}
			if err := setPermissions(ctx, tx, tenantID, roleID, keys); err != nil {
				return err
			}
		}
		if role, err = s.getRole(ctx, tx, tenantID, roleID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopeTenant(tenantID), Action: "role.update", Target: roleID, Outcome: audit.Success,
			Detail: map[string]any{
				"before": map[string]any{"name": before.Name, "enabled": before.Enabled, "permissions": before.Permissions},
				"after":  map[string]any{"name": role.Name, "enabled": role.Enabled, "permissions": role.Permissions},
			},
		})
	})
	if err != nil {
		return Role{}, err
	}
	return role, nil
}

// newPermissions checks a role's next permission list: each key either stays
// from current, or is on offer in this deployment.
func (s *Service) newPermissions(current, next []string) ([]string, error) {
	keys := slices.Clone(next)
	slices.Sort(keys)
	keys = slices.Compact(keys)
	for _, key := range keys {
		if !slices.Contains(current, key) && !s.catalog.Assignable(key) {
			return nil, fmt.Errorf("%w: %s", ErrUnknownPermission, key)
		}
	}
	return keys, nil
}

func setPermissions(ctx context.Context, tx pgx.Tx, tenantID, roleID string, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO auth.role_permissions (tenant_id, role_id, permission) SELECT $1, $2, unnest($3::text[])`,
		tenantID, roleID, keys)
	if err != nil {
		return translate(err, "set role permissions")
	}
	return nil
}

func cleanText(name, description string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxNameLength ||
		utf8.RuneCountInString(strings.TrimSpace(description)) > maxDescriptionLength {
		return "", fmt.Errorf("%w: a role needs a name of up to %d characters, and a description of up to %d",
			ErrInvalid, maxNameLength, maxDescriptionLength)
	}
	return name, nil
}

// Assignment is one member's holding of a role. Modules bind their scope to its
// ID.
type Assignment struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	RoleID    string     `json:"role_id"`
	RoleName  string     `json:"role_name"`
	Status    string     `json:"status"`
	Revision  int64      `json:"revision"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

const assignmentColumns = `a.id, m.user_id, a.role_id, r.name, a.status, a.revision, a.created_by, a.created_at, a.revoked_at`

const assignmentJoins = `FROM auth.member_role_assignments a
	JOIN auth.memberships m ON m.tenant_id = a.tenant_id AND m.id = a.membership_id
	JOIN auth.tenant_roles r ON r.tenant_id = a.tenant_id AND r.id = a.role_id`

func scanAssignment(row pgx.Row) (Assignment, error) {
	var a Assignment
	err := row.Scan(&a.ID, &a.UserID, &a.RoleID, &a.RoleName, &a.Status, &a.Revision, &a.CreatedBy, &a.CreatedAt, &a.RevokedAt)
	return a, err
}

// ListAssignments returns a member's assignments, newest first, revoked ones
// included so a module's audit can still name them.
func (s *Service) ListAssignments(ctx context.Context, tenantID, userID string) ([]Assignment, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+assignmentColumns+` `+assignmentJoins+`
		 WHERE a.tenant_id = $1 AND m.user_id = $2 ORDER BY a.status, a.created_at DESC, a.id`, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("list assignments: %w", err)
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Assignment, error) { return scanAssignment(row) })
	if err != nil {
		return nil, fmt.Errorf("list assignments: %w", err)
	}
	return list, nil
}

// Assign gives an active member an enabled role.
func (s *Service) Assign(ctx context.Context, actor, tenantID, userID, roleID string) (Assignment, error) {
	var a Assignment
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := bumpRevision(ctx, tx, tenantID); err != nil {
			return err
		}
		var membershipID string
		err := tx.QueryRow(ctx,
			`SELECT id FROM auth.memberships WHERE tenant_id = $1 AND user_id = $2 AND status = 'active'`,
			tenantID, userID).Scan(&membershipID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("find membership: %w", err)
		}
		var enabled bool
		err = tx.QueryRow(ctx, "SELECT enabled FROM auth.tenant_roles WHERE tenant_id = $1 AND id = $2 FOR SHARE",
			tenantID, roleID).Scan(&enabled)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("find role: %w", err)
		}
		if !enabled {
			return ErrRoleDisabled
		}
		id := ids.New("rla")
		_, err = tx.Exec(ctx,
			`INSERT INTO auth.member_role_assignments (id, tenant_id, membership_id, role_id, created_by)
			 VALUES ($1, $2, $3, $4, $5)`, id, tenantID, membershipID, roleID, actor)
		if err != nil {
			return translate(err, "assign role")
		}
		a, err = scanAssignment(tx.QueryRow(ctx, `SELECT `+assignmentColumns+` `+assignmentJoins+` WHERE a.id = $1`, id))
		if err != nil {
			return fmt.Errorf("read assignment: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopeTenant(tenantID), Action: "role_assignment.create", Target: userID,
			Outcome: audit.Success, Detail: map[string]any{"assignment_id": id, "role_id": roleID},
		})
	})
	if err != nil {
		return Assignment{}, err
	}
	return a, nil
}

// Revoke ends an assignment. Its ID is kept, so a module's stale scope binding
// can never restore access, and assigning again makes a new one.
func (s *Service) Revoke(ctx context.Context, actor, tenantID, userID, assignmentID string, revision int64) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := bumpRevision(ctx, tx, tenantID); err != nil {
			return err
		}
		var status, roleID string
		var current int64
		err := tx.QueryRow(ctx,
			`SELECT a.status, a.revision, a.role_id FROM auth.member_role_assignments a
			 JOIN auth.memberships m ON m.tenant_id = a.tenant_id AND m.id = a.membership_id
			 WHERE a.tenant_id = $1 AND m.user_id = $2 AND a.id = $3 FOR UPDATE OF a`,
			tenantID, userID, assignmentID).Scan(&status, &current, &roleID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("find assignment: %w", err)
		}
		if status != "active" || current != revision {
			return ErrStale
		}
		_, err = tx.Exec(ctx,
			`UPDATE auth.member_role_assignments
			 SET status = 'revoked', revision = revision + 1, revoked_by = $2, revoked_at = now() WHERE id = $1`,
			assignmentID, actor)
		if err != nil {
			return fmt.Errorf("revoke assignment: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopeTenant(tenantID), Action: "role_assignment.revoke", Target: userID,
			Outcome: audit.Success, Detail: map[string]any{"assignment_id": assignmentID, "role_id": roleID},
		})
	})
}

// Grant is one permission a user holds, with the assignment it comes from. A
// module unions scope only across the assignments that grant the action asked.
type Grant struct {
	Permission   string `json:"permission"`
	AssignmentID string `json:"assignment_id"`
	RoleID       string `json:"role_id"`
}

// UserEntitlement is one user's standing in a tenant and their grants in one
// module. Active is false, with no grants, unless the account, the tenant and
// the membership are all active.
type UserEntitlement struct {
	UserID           string  `json:"user_id"`
	Active           bool    `json:"active"`
	AccountStatus    string  `json:"account_status"`
	MembershipStatus string  `json:"membership_status"`
	TenantAdmin      bool    `json:"tenant_admin"`
	Grants           []Grant `json:"grants"`
}

// Entitlements is one module's read for a tenant: never cached by auth, and
// meant to be read on each protected request.
type Entitlements struct {
	TenantID     string            `json:"tenant_id"`
	TenantStatus string            `json:"tenant_status"`
	Module       string            `json:"module"`
	Revision     int64             `json:"revision"`
	Users        []UserEntitlement `json:"users"`
}

// EntitlementsFor answers a module's service for its own namespace only.
func (s *Service) EntitlementsFor(ctx context.Context, service, tenantID, moduleID string, userIDs []string) (Entitlements, error) {
	m, ok := s.catalog.Module(moduleID)
	if !ok {
		return Entitlements{}, ErrUnknownModule
	}
	if m.Service != service {
		return Entitlements{}, ErrNotModuleService
	}
	return s.entitlements(ctx, tenantID, m, userIDs)
}

// MyPermissions is a user's own grants in one module, as client hints.
func (s *Service) MyPermissions(ctx context.Context, tenantID, userID, moduleID string) (UserEntitlement, error) {
	m, ok := s.catalog.Module(moduleID)
	if !ok {
		return UserEntitlement{}, ErrUnknownModule
	}
	e, err := s.entitlements(ctx, tenantID, m, []string{userID})
	if err != nil {
		return UserEntitlement{}, err
	}
	return e.Users[0], nil
}

func (s *Service) entitlements(ctx context.Context, tenantID string, m Module, userIDs []string) (Entitlements, error) {
	userIDs = slices.Compact(slices.Sorted(slices.Values(userIDs)))
	if len(userIDs) == 0 || len(userIDs) > MaxEntitlementUsers || slices.Contains(userIDs, "") {
		return Entitlements{}, fmt.Errorf("%w: name between 1 and %d users", ErrInvalid, MaxEntitlementUsers)
	}
	e := Entitlements{TenantID: tenantID, Module: m.ID, Users: make([]UserEntitlement, 0, len(userIDs))}
	// One snapshot, so the revision matches the grants returned with it.
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, "SELECT status, authorization_revision FROM auth.tenants WHERE id = $1", tenantID).
			Scan(&e.TenantStatus, &e.Revision)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read tenant: %w", err)
		}
		rows, err := tx.Query(ctx,
			`SELECT q.user_id, COALESCE(u.status, ''), COALESCE(m.status, ''), COALESCE(m.role, '')
			 FROM unnest($2::text[]) AS q(user_id)
			 LEFT JOIN auth.users u ON u.id = q.user_id
			 LEFT JOIN auth.memberships m ON m.tenant_id = $1 AND m.user_id = q.user_id
			 ORDER BY q.user_id`, tenantID, userIDs)
		if err != nil {
			return fmt.Errorf("read members: %w", err)
		}
		users, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (UserEntitlement, error) {
			var u UserEntitlement
			var role string
			err := row.Scan(&u.UserID, &u.AccountStatus, &u.MembershipStatus, &role)
			u.Active = e.TenantStatus == "active" && u.AccountStatus == "active" && u.MembershipStatus == "active"
			u.TenantAdmin = u.Active && role == "admin"
			u.Grants = []Grant{}
			return u, err
		})
		if err != nil {
			return fmt.Errorf("read members: %w", err)
		}
		rows, err = tx.Query(ctx,
			`SELECT m.user_id, rp.permission, a.id, r.id
			 FROM auth.member_role_assignments a
			 JOIN auth.memberships m ON m.tenant_id = a.tenant_id AND m.id = a.membership_id
			 JOIN auth.tenant_roles r ON r.tenant_id = a.tenant_id AND r.id = a.role_id
			 JOIN auth.role_permissions rp ON rp.tenant_id = r.tenant_id AND rp.role_id = r.id
			 WHERE a.tenant_id = $1 AND m.user_id = ANY($2) AND a.status = 'active' AND r.enabled
			   AND split_part(rp.permission, ':', 1) = $3
			 ORDER BY m.user_id, rp.permission, a.id`, tenantID, userIDs, m.Prefix)
		if err != nil {
			return fmt.Errorf("read grants: %w", err)
		}
		var userID string
		var g Grant
		_, err = pgx.ForEachRow(rows, []any{&userID, &g.Permission, &g.AssignmentID, &g.RoleID}, func() error {
			i := slices.IndexFunc(users, func(u UserEntitlement) bool { return u.UserID == userID })
			if i >= 0 && users[i].Active && s.catalog.Grants(g.Permission) {
				users[i].Grants = append(users[i].Grants, g)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("read grants: %w", err)
		}
		e.Users = users
		return nil
	})
	if err != nil {
		return Entitlements{}, err
	}
	return e, nil
}

// Access is what /v1/me/access adds: the deployed modules a user holds any
// permission in, and those whose settings they may administer. A tenant admin
// administers every one.
func (s *Service) Access(ctx context.Context, tenantID, userID string, tenantAdmin bool) (modules, moduleAdmin []string, err error) {
	modules, moduleAdmin = []string{}, []string{}
	if tenantID == "" {
		return modules, moduleAdmin, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT rp.permission
		 FROM auth.member_role_assignments a
		 JOIN auth.memberships m ON m.tenant_id = a.tenant_id AND m.id = a.membership_id
		 JOIN auth.users u ON u.id = m.user_id
		 JOIN auth.tenants t ON t.id = a.tenant_id
		 JOIN auth.tenant_roles r ON r.tenant_id = a.tenant_id AND r.id = a.role_id
		 JOIN auth.role_permissions rp ON rp.tenant_id = r.tenant_id AND rp.role_id = r.id
		 WHERE a.tenant_id = $1 AND m.user_id = $2 AND a.status = 'active' AND r.enabled
		   AND m.status = 'active' AND u.status = 'active' AND t.status = 'active'`, tenantID, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("read access: %w", err)
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, nil, fmt.Errorf("read access: %w", err)
	}
	for _, m := range s.catalog.modules {
		held := slices.ContainsFunc(keys, func(k string) bool {
			return strings.HasPrefix(k, m.Prefix+":") && s.catalog.Grants(k)
		})
		if held || tenantAdmin {
			modules = append(modules, m.ID)
		}
		if tenantAdmin || (slices.Contains(keys, m.Prefix+":admin") && s.catalog.Grants(m.Prefix+":admin")) {
			moduleAdmin = append(moduleAdmin, m.ID)
		}
	}
	return modules, moduleAdmin, nil
}

// Purge removes a module's permissions from every tenant's role, for a module
// retired for good. Roles and assignments stay, even ones left with nothing.
// It refuses while the module is in this deployment's catalog.
func (s *Service) Purge(ctx context.Context, actor, moduleID string) (int64, error) {
	if _, ok := s.catalog.Module(moduleID); ok {
		return 0, ErrDeployed
	}
	var removed int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT DISTINCT rp.tenant_id FROM auth.role_permissions rp
			 JOIN auth.permission_definitions d ON d.key = rp.permission
			 WHERE d.module = $1 ORDER BY rp.tenant_id`, moduleID)
		if err != nil {
			return fmt.Errorf("find tenants: %w", err)
		}
		tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return fmt.Errorf("find tenants: %w", err)
		}
		for _, tenantID := range tenants {
			if _, err := bumpRevision(ctx, tx, tenantID); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx,
				`DELETE FROM auth.role_permissions rp USING auth.permission_definitions d
				 WHERE d.key = rp.permission AND d.module = $1 AND rp.tenant_id = $2`, moduleID, tenantID)
			if err != nil {
				return fmt.Errorf("purge role permissions: %w", err)
			}
			removed += tag.RowsAffected()
			err = audit.Write(ctx, tx, audit.Entry{
				Actor: actor, Scope: audit.ScopeTenant(tenantID), Action: "role.purge_module", Target: moduleID,
				Outcome: audit.Success, Detail: map[string]any{"removed": tag.RowsAffected()},
			})
			if err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, "DELETE FROM auth.permission_definitions WHERE module = $1", moduleID); err != nil {
			return fmt.Errorf("purge definitions: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopePlatform, Action: "permissions.purge", Target: moduleID, Outcome: audit.Success,
			Detail: map[string]any{"tenants": len(tenants), "removed": removed},
		})
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
}

// bumpRevision raises a tenant's authorization revision. Its row lock also
// serializes two admins changing the same tenant's roles.
func bumpRevision(ctx context.Context, tx pgx.Tx, tenantID string) (int64, error) {
	var revision int64
	err := tx.QueryRow(ctx,
		"UPDATE auth.tenants SET authorization_revision = authorization_revision + 1 WHERE id = $1 RETURNING authorization_revision",
		tenantID).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("raise authorization revision: %w", err)
	}
	return revision, nil
}

func translate(err error, what string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return ErrExists
		case "23503":
			return fmt.Errorf("%w: %s", ErrUnknownPermission, pgErr.Detail)
		case "23514":
			return ErrInvalid
		}
	}
	return fmt.Errorf("%s: %w", what, err)
}
