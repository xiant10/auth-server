package identity

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/ids"
)

const (
	totpPeriod = 30
	totpIssuer = "t10"
)

// ErrTOTPEnrolled means an authenticator is already on.
var ErrTOTPEnrolled = errors.New("TOTP is already enrolled")

// ErrMFAMandatory means this account may not drop its second factor.
var ErrMFAMandatory = errors.New("this account must keep a second factor")

func totpOpts() totp.ValidateOpts {
	return totp.ValidateOpts{Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
}

// TOTPCode computes the code for a secret at t.
func TOTPCode(secret string, t time.Time) (string, error) {
	return totp.GenerateCodeCustom(secret, t, totpOpts())
}

func (s *Service) seal(userID, secret string) ([]byte, error) {
	aead, err := s.aead()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce) // Never fails; see crypto/rand.
	return aead.Seal(nonce, nonce, []byte(secret), []byte(userID)), nil
}

func (s *Service) unseal(userID string, sealed []byte) (string, error) {
	aead, err := s.aead()
	if err != nil {
		return "", err
	}
	if len(sealed) < aead.NonceSize() {
		return "", errors.New("sealed TOTP secret is too short")
	}
	nonce, body := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, body, []byte(userID))
	if err != nil {
		return "", fmt.Errorf("open TOTP secret: %w", err)
	}
	return string(plain), nil
}

func (s *Service) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.totpKey)
	if err != nil {
		return nil, fmt.Errorf("TOTP key: %w", err)
	}
	return cipher.NewGCM(block)
}

func (s *Service) hasTOTP(ctx context.Context, userID string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM auth.mfa_factors WHERE user_id = $1 AND verified_at IS NOT NULL)", userID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check MFA: %w", err)
	}
	return ok, nil
}

// verifyTOTP accepts the current step and one either side. A step at or before
// last_used_step is refused, so each code works once.
func (s *Service) verifyTOTP(ctx context.Context, userID, code string) (bool, error) {
	var valid bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		valid, err = s.consumeTOTP(ctx, tx, userID, code, true)
		return err
	})
	return valid, err
}

func (s *Service) consumeTOTP(ctx context.Context, tx pgx.Tx, userID, code string, verifiedOnly bool) (bool, error) {
	var sealed []byte
	var last int64
	var verifiedAt *time.Time
	err := tx.QueryRow(ctx,
		`SELECT secret_encrypted, last_used_step, verified_at FROM auth.mfa_factors
		 WHERE user_id = $1 AND kind = 'totp' FOR UPDATE`, userID).Scan(&sealed, &last, &verifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("load factor: %w", err)
	}
	if verifiedOnly && verifiedAt == nil {
		return false, nil
	}
	secret, err := s.unseal(userID, sealed)
	if err != nil {
		return false, err
	}

	code = strings.TrimSpace(code)
	now := time.Now().Unix() / totpPeriod
	for step := now - 1; step <= now+1; step++ {
		if step <= last {
			continue
		}
		want, err := TOTPCode(secret, time.Unix(step*totpPeriod, 0))
		if err != nil {
			return false, fmt.Errorf("compute code: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			_, err := tx.Exec(ctx,
				"UPDATE auth.mfa_factors SET last_used_step = $2, verified_at = COALESCE(verified_at, now()) WHERE user_id = $1 AND kind = 'totp'",
				userID, step)
			if err != nil {
				return false, fmt.Errorf("record code: %w", err)
			}
			return true, nil
		}
	}
	return false, nil
}

// TOTPEnrollment is what a user adds to an authenticator app.
type TOTPEnrollment struct {
	Secret string
	URL    string
}

// StartTOTP creates an unverified factor. It counts for nothing until
// ConfirmTOTP proves the app holds the secret.
func (s *Service) StartTOTP(ctx context.Context, userID, label string, r Reauth) (TOTPEnrollment, error) {
	if err := s.checkReauth(ctx, userID, "totp_start", r); err != nil {
		return TOTPEnrollment{}, err
	}
	enrolled, err := s.hasTOTP(ctx, userID)
	if err != nil {
		return TOTPEnrollment{}, err
	}
	if enrolled {
		return TOTPEnrollment{}, ErrTOTPEnrolled
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: totpIssuer, AccountName: label, Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("generate TOTP secret: %w", err)
	}
	sealed, err := s.seal(userID, key.Secret())
	if err != nil {
		return TOTPEnrollment{}, err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO auth.mfa_factors (id, user_id, kind, secret_encrypted) VALUES ($1, $2, 'totp', $3)
		 ON CONFLICT (user_id, kind) DO UPDATE SET secret_encrypted = EXCLUDED.secret_encrypted, last_used_step = 0, verified_at = NULL`,
		ids.New("mfa"), userID, sealed)
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("store factor: %w", err)
	}
	return TOTPEnrollment{Secret: key.Secret(), URL: key.URL()}, nil
}

// ConfirmTOTP activates a started factor and marks this session as having
// proved it. Other sessions end, since the account's strength changed.
func (s *Service) ConfirmTOTP(ctx context.Context, userID, sessionID, code string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		ok, err := s.consumeTOTP(ctx, tx, userID, code, false)
		if err != nil {
			return err
		}
		if !ok {
			return ErrInvalidCredentials
		}
		if _, err := tx.Exec(ctx, "UPDATE auth.sessions SET mfa_at = now() WHERE id = $1", sessionID); err != nil {
			return fmt.Errorf("mark session: %w", err)
		}
		if err := revokeSessions(ctx, tx, userID, sessionID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "mfa.enroll", Target: userID, Outcome: audit.Success,
		})
	})
}

// DisableTOTP removes the factor, unless a role or tenant policy needs it.
// Browser and client sessions stop counting as having proved one. App sessions
// keep theirs, because the device itself is the factor.
func (s *Service) DisableTOTP(ctx context.Context, userID string, r Reauth) error {
	if err := s.checkReauth(ctx, userID, "totp_disable", r); err != nil {
		return err
	}
	mandatory, err := s.tenants.MFAMandatory(ctx, userID)
	if err != nil {
		return err
	}
	if mandatory {
		return ErrMFAMandatory
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM auth.mfa_factors WHERE user_id = $1", userID); err != nil {
			return fmt.Errorf("delete factor: %w", err)
		}
		if _, err := tx.Exec(ctx, "UPDATE auth.sessions SET mfa_at = NULL WHERE user_id = $1 AND device_id IS NULL", userID); err != nil {
			return fmt.Errorf("clear session factors: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "mfa.remove", Target: userID, Outcome: audit.Success,
		})
	})
}
