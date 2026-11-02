package directory

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"t10-auth-server/internal/audit"
)

// Platform role errors.
var (
	// ErrLastPlatformAdmin means a change would leave no platform admin.
	ErrLastPlatformAdmin = errors.New("the platform needs at least one admin")
	// ErrUserSuspended means a suspended account can't take the platform role.
	ErrUserSuspended = errors.New("user is suspended")
)

// UserSummary is one row of the platform's user list.
type UserSummary struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Status        string    `json:"status"`
	PlatformAdmin bool      `json:"platform_admin"`
	Tenants       int       `json:"tenants"`
	CreatedAt     time.Time `json:"created_at"`
}

// ListUsers returns up to limit users with a sign-in name containing search, or
// with exactly that ID, platform admins first.
func (s *Service) ListUsers(ctx context.Context, search string, limit int) ([]UserSummary, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT u.id,
		        COALESCE((SELECT i.value FROM auth.user_identifiers i
		                  WHERE i.user_id = u.id ORDER BY i.created_at, i.value LIMIT 1), ''),
		        u.status, a.user_id IS NOT NULL,
		        (SELECT count(*) FROM auth.memberships m WHERE m.user_id = u.id AND m.status = 'active'),
		        u.created_at
		 FROM auth.users u
		 LEFT JOIN auth.platform_admins a ON a.user_id = u.id
		 WHERE $1 = '' OR u.id = $1
		    OR EXISTS (SELECT 1 FROM auth.user_identifiers i
		               WHERE i.user_id = u.id AND position(lower($1) IN lower(i.value)) > 0)
		 ORDER BY a.user_id IS NULL, u.created_at DESC, u.id LIMIT $2`, search, limit)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	users, err := pgx.CollectRows(rows, pgx.RowToStructByPos[UserSummary])
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

// AddPlatformAdmin gives an existing, active user the platform role.
func (s *Service) AddPlatformAdmin(ctx context.Context, actor, userID string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Locking the user serializes this with a suspension.
		var status string
		err := tx.QueryRow(ctx, "SELECT status FROM auth.users WHERE id = $1 FOR UPDATE", userID).Scan(&status)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("lock user: %w", err)
		}
		if status != "active" {
			return ErrUserSuspended
		}
		return s.GrantPlatformAdmin(ctx, tx, actor, userID)
	})
}

// RemovePlatformAdmin takes the platform role away. It applies at once, because
// every platform action reads the table. It refuses to remove the last holder.
func (s *Service) RemovePlatformAdmin(ctx context.Context, actor, userID string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Locking every row serializes two admins removing each other.
		rows, err := tx.Query(ctx, "SELECT user_id FROM auth.platform_admins ORDER BY user_id FOR UPDATE")
		if err != nil {
			return fmt.Errorf("lock platform admins: %w", err)
		}
		holders, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return fmt.Errorf("lock platform admins: %w", err)
		}
		found := false
		for _, holder := range holders {
			found = found || holder == userID
		}
		if !found {
			return ErrNotFound
		}
		if len(holders) == 1 {
			return ErrLastPlatformAdmin
		}
		if _, err := tx.Exec(ctx, "DELETE FROM auth.platform_admins WHERE user_id = $1", userID); err != nil {
			return fmt.Errorf("remove platform admin: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopePlatform, Action: "platform_admin.remove", Target: userID, Outcome: audit.Success,
		})
	})
}
