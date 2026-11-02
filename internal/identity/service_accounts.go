package identity

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"t10-auth-server/internal/audit"
)

// Service account statuses.
const (
	ServiceActive   = "active"
	ServiceDisabled = "disabled"
)

// ErrServiceAccount covers a service account request that can't be applied.
var ErrServiceAccount = errors.New("service account request refused")

var serviceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)

const (
	servicePrefix    = "svc_"
	minServiceSecret = 32
)

// ServiceAccount is a stable runtime or microservice. Dynamic agents never
// have one.
type ServiceAccount struct {
	ID   string
	Name string
}

// AddServiceAccount registers a service and returns its secret. An empty secret
// means a new random one. A supplied one comes from the operator's secret store,
// and is only ever hashed once, so it has to be long.
func (s *Service) AddServiceAccount(ctx context.Context, actor, name, secret string) (string, error) {
	if !serviceNamePattern.MatchString(name) || name == AudienceT10 {
		return "", fmt.Errorf("%w: invalid name %q", ErrServiceAccount, name)
	}
	if secret == "" {
		secret = randomSecret()
	}
	if len(secret) < minServiceSecret {
		return "", fmt.Errorf("%w: a secret needs %d or more characters", ErrServiceAccount, minServiceSecret)
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO auth.service_accounts (id, name, secret_hash) VALUES ($1, $2, $3)",
			servicePrefix+name, name, hashSecret(secret))
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("%w: %s already exists", ErrServiceAccount, name)
		}
		if err != nil {
			return fmt.Errorf("add service account: %w", err)
		}
		return s.auditService(ctx, tx, actor, "service_account.create", name)
	})
	if err != nil {
		return "", err
	}
	return secret, nil
}

// HasServiceAccount reports whether a service is registered.
func (s *Service) HasServiceAccount(ctx context.Context, name string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM auth.service_accounts WHERE name = $1)", name).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check service account: %w", err)
	}
	return exists, nil
}

// RotateServiceSecret adds a second valid secret. The old one keeps working
// until FinishServiceRotation, so every replica can move over first.
func (s *Service) RotateServiceSecret(ctx context.Context, actor, name string) (string, error) {
	secret := randomSecret()
	err := s.updateService(ctx, actor, "service_account.rotate", name,
		"UPDATE auth.service_accounts SET next_secret_hash = $2 WHERE name = $1", hashSecret(secret))
	if err != nil {
		return "", err
	}
	return secret, nil
}

// FinishServiceRotation retires the old secret.
func (s *Service) FinishServiceRotation(ctx context.Context, actor, name string) error {
	return s.updateService(ctx, actor, "service_account.rotate_finish", name,
		`UPDATE auth.service_accounts SET secret_hash = next_secret_hash, next_secret_hash = NULL
		 WHERE name = $1 AND next_secret_hash IS NOT NULL`)
}

// SetServiceStatus enables or disables a service. Disabling stops token
// exchange at once, for every grant the service holds.
func (s *Service) SetServiceStatus(ctx context.Context, actor, name, status string) error {
	if status != ServiceActive && status != ServiceDisabled {
		return fmt.Errorf("%w: invalid status %q", ErrServiceAccount, status)
	}
	return s.updateService(ctx, actor, "service_account.status", name,
		"UPDATE auth.service_accounts SET status = $2 WHERE name = $1", status)
}

func (s *Service) updateService(ctx context.Context, actor, action, name, sql string, args ...any) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, sql, append([]any{name}, args...)...)
		if err != nil {
			return fmt.Errorf("update service account: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: no change for %s", ErrServiceAccount, name)
		}
		return s.auditService(ctx, tx, actor, action, name)
	})
}

func (s *Service) auditService(ctx context.Context, tx pgx.Tx, actor, action, name string) error {
	return audit.Write(ctx, tx, audit.Entry{
		Actor: actor, Scope: audit.ScopePlatform, Action: action, Target: name, Outcome: audit.Success,
	})
}

// ServiceLogin checks a service's secret. Secrets hold 256 random bits, so a
// fast hash is enough, and the failure is the same for every reason.
func (s *Service) ServiceLogin(ctx context.Context, name, secret string) (ServiceAccount, error) {
	var account ServiceAccount
	var current, next []byte
	err := s.pool.QueryRow(ctx,
		"SELECT id, name, secret_hash, next_secret_hash FROM auth.service_accounts WHERE name = $1 AND status = 'active'",
		name).Scan(&account.ID, &account.Name, &current, &next)
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceAccount{}, ErrInvalidClient
	}
	if err != nil {
		return ServiceAccount{}, fmt.Errorf("read service account: %w", err)
	}
	presented := hashSecret(secret)
	valid := subtle.ConstantTimeCompare(presented, current) | subtle.ConstantTimeCompare(presented, next)
	if secret == "" || valid != 1 {
		return ServiceAccount{}, ErrInvalidClient
	}
	return account, nil
}

// ServiceToken is the client_credentials grant.
func (s *Service) ServiceToken(ctx context.Context, name, secret string) (Tokens, error) {
	account, err := s.ServiceLogin(ctx, name, secret)
	if err != nil {
		return Tokens{}, err
	}
	token, expires, err := s.issuer.MintService(account.ID)
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{Access: token, ExpiresAt: expires}, nil
}

// AuthenticateService checks a service token. Its subject has to be an active
// service account, which also refuses a user's token, and reading status every
// time stops a disabled service at once rather than when its token runs out.
func (s *Service) AuthenticateService(ctx context.Context, raw string) (ServiceAccount, error) {
	claims, err := s.issuer.Verify(raw)
	if err != nil {
		return ServiceAccount{}, err
	}
	account := ServiceAccount{ID: claims.Subject}
	err = s.pool.QueryRow(ctx, "SELECT name FROM auth.service_accounts WHERE id = $1 AND status = 'active'",
		claims.Subject).Scan(&account.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceAccount{}, fmt.Errorf("%w: service disabled", ErrInvalidToken)
	}
	if err != nil {
		return ServiceAccount{}, fmt.Errorf("check service account: %w", err)
	}
	return account, nil
}
