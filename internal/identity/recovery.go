package identity

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"t10-auth-server/internal/audit"
)

const (
	recoveryCodeCount = 10
	resetTokenTTL     = 30 * time.Minute
)

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func newRecoveryCode() string {
	b := make([]byte, 10)
	rand.Read(b) // Never fails; see crypto/rand.
	raw := strings.ToLower(recoveryEncoding.EncodeToString(b))
	return raw[:4] + "-" + raw[4:8] + "-" + raw[8:12] + "-" + raw[12:]
}

// hashRecoveryCode ignores case, spacing and dashes, which people get wrong
// when copying a code. The code's 80 random bits make a fast hash safe.
func hashRecoveryCode(code string) []byte {
	clean := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(code))
	return hashSecret(clean)
}

// IssueRecoveryCodes replaces a user's codes inside tx and returns the new
// ones, which exist nowhere else after this.
func (s *Service) IssueRecoveryCodes(ctx context.Context, tx pgx.Tx, userID string) ([]string, error) {
	if _, err := tx.Exec(ctx, "DELETE FROM auth.recovery_codes WHERE user_id = $1", userID); err != nil {
		return nil, fmt.Errorf("clear recovery codes: %w", err)
	}
	codes := make([]string, recoveryCodeCount)
	for i := range codes {
		codes[i] = newRecoveryCode()
		_, err := tx.Exec(ctx, "INSERT INTO auth.recovery_codes (user_id, code_hash) VALUES ($1, $2)", userID, hashRecoveryCode(codes[i]))
		if err != nil {
			return nil, fmt.Errorf("store recovery code: %w", err)
		}
	}
	return codes, nil
}

func useRecoveryCode(ctx context.Context, tx pgx.Tx, userID, code string) (bool, error) {
	tag, err := tx.Exec(ctx,
		"UPDATE auth.recovery_codes SET used_at = now() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL",
		userID, hashRecoveryCode(code))
	if err != nil {
		return false, fmt.Errorf("use recovery code: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// Recovery is a password reset by recovery code.
type Recovery struct {
	Name        string
	Code        string
	SecondCode  string
	TOTP        string
	NewPassword string
	IP          string
}

// Recover resets a password with a recovery code. An MFA account also needs its
// TOTP code or a second recovery code. Taking the second route drops the TOTP
// factor, because that route exists for a lost authenticator.
func (s *Service) Recover(ctx context.Context, r Recovery) error {
	if err := s.allowIP(ctx, "recover:ip", r.IP, s.limits.RecoverIP); err != nil {
		return err
	}
	if err := s.allowAccount(ctx, "recover:acct", r.Name, s.limits.RecoverAccount); err != nil {
		return err
	}
	if err := checkPassword(r.NewPassword, r.Name); err != nil {
		return err
	}
	c, err := s.lookupByName(ctx, r.Name)
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrInvalidName) {
		// No dummy hash here, unlike sign-in: a wrong code on a real account
		// never reaches a hash either, so one would mark the unknown names.
		s.deny(ctx, "anonymous", "", "recovery_refused")
		return ErrInvalidCredentials
	}
	if err != nil {
		return err
	}
	if c.status != "active" {
		return ErrInvalidCredentials
	}
	enrolled, err := s.hasTOTP(ctx, c.userID)
	if err != nil {
		return err
	}

	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		ok, err := useRecoveryCode(ctx, tx, c.userID, r.Code)
		if err != nil {
			return err
		}
		if !ok {
			return ErrInvalidCredentials
		}
		method := "recovery_code"
		if enrolled {
			if method, err = s.secondRecoveryProof(ctx, tx, c.userID, r); err != nil {
				return err
			}
		}
		if err := s.setPassword(ctx, tx, c.userID, r.NewPassword, ""); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(c.userID), Scope: audit.ScopePlatform, Action: "password.recover", Target: c.userID,
			Outcome: audit.Success, Detail: map[string]any{"method": method},
		})
	})
	if errors.Is(err, ErrInvalidCredentials) {
		s.recordFailure(ctx, c.userID)
		s.deny(ctx, audit.ActorUser(c.userID), c.userID, "recovery_refused")
	}
	return err
}

func (s *Service) secondRecoveryProof(ctx context.Context, tx pgx.Tx, userID string, r Recovery) (string, error) {
	if r.TOTP != "" {
		ok, err := s.consumeTOTP(ctx, tx, userID, r.TOTP, true)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", ErrInvalidCredentials
		}
		return "recovery_code+totp", nil
	}
	if r.SecondCode == "" {
		return "", ErrInvalidCredentials
	}
	ok, err := useRecoveryCode(ctx, tx, userID, r.SecondCode)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrInvalidCredentials
	}
	if _, err := tx.Exec(ctx, "DELETE FROM auth.mfa_factors WHERE user_id = $1", userID); err != nil {
		return "", fmt.Errorf("drop factor: %w", err)
	}
	return "two_recovery_codes", nil
}

// setPassword stores a new hash, clears lockout, cancels unused reset links and
// ends sessions but except.
func (s *Service) setPassword(ctx context.Context, tx pgx.Tx, userID, password, except string) error {
	hash, err := s.hasher.Hash(ctx, password)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`UPDATE auth.credentials
		 SET password_hash = $2, password_changed_at = now(), failed_count = 0, locked_until = NULL
		 WHERE user_id = $1`, userID, hash)
	if err != nil {
		return fmt.Errorf("store password: %w", err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM auth.reset_tokens WHERE user_id = $1 AND used_at IS NULL", userID); err != nil {
		return fmt.Errorf("clear reset links: %w", err)
	}
	return revokeAccess(ctx, tx, userID, except)
}

// IssueReset creates a single-use reset link token. The caller has already
// decided the actor may reset this user.
func (s *Service) IssueReset(ctx context.Context, actor, scope, userID string) (string, error) {
	token := randomSecret()
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			"INSERT INTO auth.reset_tokens (token_hash, user_id, issued_by, expires_at) VALUES ($1, $2, $3, $4)",
			hashSecret(token), userID, actor, time.Now().Add(resetTokenTTL))
		if err != nil {
			return fmt.Errorf("store reset token: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: scope, Action: "password.reset_issue", Target: userID, Outcome: audit.Success,
		})
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// ResetPassword spends a reset token. An enrolled TOTP factor survives, so an
// admin who issues a link still cannot sign in as the user.
func (s *Service) ResetPassword(ctx context.Context, token, password string) error {
	if err := checkPassword(password); err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var userID string
		err := tx.QueryRow(ctx,
			`UPDATE auth.reset_tokens SET used_at = now()
			 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
			 RETURNING user_id`, hashSecret(token)).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidCredentials
		}
		if err != nil {
			return fmt.Errorf("spend reset token: %w", err)
		}
		if err := s.setPassword(ctx, tx, userID, password, ""); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "password.reset", Target: userID, Outcome: audit.Success,
		})
	})
}
