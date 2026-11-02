package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"t10-auth-server/internal/audit"
)

// SignInName is one of an account's names.
type SignInName struct {
	Kind  string
	Value string
}

// Device is one enrolled app.
type Device struct {
	ID         string
	Name       string
	Platform   string
	LastUsedAt *time.Time
	CreatedAt  time.Time
}

// Account is what the account page and GET /v1/me show.
type Account struct {
	DisplayName   string
	Names         []SignInName
	TOTP          bool
	RecoveryCodes int
	Devices       []Device
}

// Label names the account in an authenticator app. Releasing a disputed name
// can leave an account with none.
func (a Account) Label() string {
	if len(a.Names) == 0 {
		return "account"
	}
	return a.Names[0].Value
}

// Normalize applies this service's name rules.
func (s *Service) Normalize(name string) (kind, value string, err error) {
	return NormalizeName(name, s.region)
}

// GetAccount loads a user's account summary.
func (s *Service) GetAccount(ctx context.Context, userID string) (Account, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT kind, value FROM auth.user_identifiers WHERE user_id = $1 ORDER BY created_at, value", userID)
	if err != nil {
		return Account{}, fmt.Errorf("list names: %w", err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowToStructByPos[SignInName])
	if err != nil {
		return Account{}, fmt.Errorf("list names: %w", err)
	}
	a := Account{Names: names}
	if err := s.pool.QueryRow(ctx, "SELECT display_name FROM auth.users WHERE id = $1", userID).Scan(&a.DisplayName); err != nil {
		return Account{}, fmt.Errorf("load user: %w", err)
	}
	rows, err = s.pool.Query(ctx,
		`SELECT id, name, platform, last_used_at, created_at FROM auth.devices
		 WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at`, userID)
	if err != nil {
		return Account{}, fmt.Errorf("list devices: %w", err)
	}
	if a.Devices, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Device]); err != nil {
		return Account{}, fmt.Errorf("list devices: %w", err)
	}
	if a.TOTP, err = s.hasTOTP(ctx, userID); err != nil {
		return Account{}, err
	}
	err = s.pool.QueryRow(ctx,
		"SELECT count(*) FROM auth.recovery_codes WHERE user_id = $1 AND used_at IS NULL", userID).Scan(&a.RecoveryCodes)
	if err != nil {
		return Account{}, fmt.Errorf("count recovery codes: %w", err)
	}
	return a, nil
}

// SetDisplayName changes the name teammates see. It's no credential, so it needs
// no reauthentication, and it can't be cleared once set.
func (s *Service) SetDisplayName(ctx context.Context, userID, name string) error {
	name, err := cleanDisplayName(name)
	if err != nil {
		return err
	}
	if name == "" {
		return ErrInvalidDisplayName
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "UPDATE auth.users SET display_name = $2 WHERE id = $1", userID, name); err != nil {
			return fmt.Errorf("update display name: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "display_name.change", Target: userID, Outcome: audit.Success,
		})
	})
}

// ChangePassword replaces a password after reauthentication. Other sessions end.
func (s *Service) ChangePassword(ctx context.Context, userID, sessionID, next string, r Reauth) error {
	if err := checkPassword(next); err != nil {
		return err
	}
	if err := s.checkReauth(ctx, userID, "password", r); err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.setPassword(ctx, tx, userID, next, sessionID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "password.change", Target: userID, Outcome: audit.Success,
		})
	})
}

// AddName attaches a sign-in name after reauthentication.
func (s *Service) AddName(ctx context.Context, userID, name string, r Reauth) error {
	kind, value, err := NormalizeName(name, s.region)
	if err != nil {
		return err
	}
	if err := s.checkReauth(ctx, userID, "name_add", r); err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := insertName(ctx, tx, userID, kind, value); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "name.add", Target: userID,
			Outcome: audit.Success, Detail: map[string]any{"kind": kind},
		})
	})
}

// RemoveName detaches a name after reauthentication, keeping at least one.
func (s *Service) RemoveName(ctx context.Context, userID, kind, value string, r Reauth) error {
	if err := s.checkReauth(ctx, userID, "name_remove", r); err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Locking the user serializes two removals that would each see a spare.
		if _, err := tx.Exec(ctx, "SELECT 1 FROM auth.users WHERE id = $1 FOR UPDATE", userID); err != nil {
			return fmt.Errorf("lock user: %w", err)
		}
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM auth.user_identifiers WHERE user_id = $1", userID).Scan(&count); err != nil {
			return fmt.Errorf("count names: %w", err)
		}
		if count <= 1 {
			return ErrLastName
		}
		tag, err := tx.Exec(ctx, "DELETE FROM auth.user_identifiers WHERE user_id = $1 AND kind = $2 AND value = $3", userID, kind, value)
		if err != nil {
			return fmt.Errorf("delete name: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "name.remove", Target: userID,
			Outcome: audit.Success, Detail: map[string]any{"kind": kind},
		})
	})
}

// RegenerateRecoveryCodes replaces the codes after reauthentication.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, userID string, r Reauth) ([]string, error) {
	if err := s.checkReauth(ctx, userID, "recovery_codes", r); err != nil {
		return nil, err
	}
	var codes []string
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		if codes, err = s.IssueRecoveryCodes(ctx, tx, userID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "recovery_codes.regenerate", Target: userID, Outcome: audit.Success,
		})
	})
	return codes, err
}

// SignOutEverywhere ends every session of a user, the current one included.
func (s *Service) SignOutEverywhere(ctx context.Context, userID string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := revokeAccess(ctx, tx, userID, ""); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "session.revoke_all", Target: userID, Outcome: audit.Success,
		})
	})
}

// SetUserStatus suspends or reactivates an account in every tenant. Suspension
// ends all its sessions and agent runs, and reactivating brings neither back. A
// platform admin must lose the role first, so the last one can't be suspended.
func (s *Service) SetUserStatus(ctx context.Context, actor, userID, status string) error {
	if status != UserActive && status != UserSuspended {
		return fmt.Errorf("invalid user status %q", status)
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Locking the user serializes this with a grant of the platform role.
		var current string
		err := tx.QueryRow(ctx, "SELECT status FROM auth.users WHERE id = $1 FOR UPDATE", userID).Scan(&current)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserNotFound
		}
		if err != nil {
			return fmt.Errorf("lock user: %w", err)
		}
		if status == UserSuspended {
			admin, err := s.tenants.IsPlatformAdminIn(ctx, tx, userID)
			if err != nil {
				return err
			}
			if admin {
				return ErrPlatformAdminUser
			}
			if err := revokeAccess(ctx, tx, userID, ""); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, "UPDATE auth.users SET status = $2 WHERE id = $1", userID, status); err != nil {
			return fmt.Errorf("update user status: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopePlatform, Action: "user.status", Target: userID,
			Outcome: audit.Success, Detail: map[string]any{"from": current, "to": status},
		})
	})
}

// ReleaseName frees a disputed name. It may leave the holder with no name, in
// which case an admin reset link is how they return.
func (s *Service) ReleaseName(ctx context.Context, actor, name string) error {
	kind, value, err := NormalizeName(name, s.region)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var userID string
		err := tx.QueryRow(ctx,
			"DELETE FROM auth.user_identifiers WHERE kind = $1 AND value = $2 RETURNING user_id", kind, value).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidName
		}
		if err != nil {
			return fmt.Errorf("release name: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopePlatform, Action: "name.release", Target: userID,
			Outcome: audit.Success, Detail: map[string]any{"kind": kind},
		})
	})
}
