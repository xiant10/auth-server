// Package identity owns users, credentials, MFA, sessions and token issuance.
package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"t10-auth-server/internal/agents"
	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/db"
	"t10-auth-server/internal/ids"
)

const (
	// devClientID names the sessions the dev password grant creates. They use
	// the Mac client's lifetimes, since that is what the grant serves.
	devClientID    = "t10-mac-client"
	devIdleTTL     = 30 * 24 * time.Hour
	devAbsoluteTTL = 90 * 24 * time.Hour

	browserClientID    = "browser"
	browserIdleTTL     = 12 * time.Hour
	browserAbsoluteTTL = 7 * 24 * time.Hour

	// PlatformMFAWindow is how recently a session must have proved a second
	// factor to take a platform action.
	PlatformMFAWindow = 15 * time.Minute
)

// Errors returned by the service.
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrNameTaken          = errors.New("sign-in name is taken")
	ErrMFARequired        = errors.New("a second factor is required")
	ErrLastName           = errors.New("an account needs at least one sign-in name")
	ErrInvalidDisplayName = errors.New("invalid display name")
	ErrUserNotFound       = errors.New("no such user")
	// ErrPlatformAdminUser means a platform admin can't be suspended.
	ErrPlatformAdminUser = errors.New("remove the platform role first")
)

// A user's status.
const (
	UserActive    = "active"
	UserSuspended = "suspended"
)

// TenantResolver is what identity needs from the directory.
type TenantResolver interface {
	// ResolveTenant checks requested against the user's active memberships. An
	// empty requested value picks the sole membership.
	ResolveTenant(ctx context.Context, q db.Querier, userID, requested string) (string, error)
	// TenantRequiresMFA reports whether a tenant demands a second factor.
	TenantRequiresMFA(ctx context.Context, q db.Querier, tenantID string) (bool, error)
	// MFAMandatory reports whether a user must keep a second factor.
	MFAMandatory(ctx context.Context, userID string) (bool, error)
	// IsPlatformAdminIn reports whether a user holds the platform role, as seen
	// by q.
	IsPlatformAdminIn(ctx context.Context, q db.Querier, userID string) (bool, error)
	// IsTenantRequired reports whether err from ResolveTenant means the user
	// has several tenants and must pick one.
	IsTenantRequired(err error) bool
}

// Options configures the module.
type Options struct {
	Pool    *pgxpool.Pool
	Hasher  *Hasher
	Issuer  *Issuer
	Tenants TenantResolver
	Clients []Client
	// Region is the default for phone numbers with no country code.
	Region string
	// TOTPKey is the 32-byte AES key for stored TOTP secrets.
	TOTPKey []byte
	Limits  Limits
}

// Service is the identity module.
type Service struct {
	pool    *pgxpool.Pool
	hasher  *Hasher
	issuer  *Issuer
	tenants TenantResolver
	clients map[string]Client
	region  string
	totpKey []byte
	limits  Limits
}

// NewService builds the module.
func NewService(o Options) *Service {
	clients := make(map[string]Client, len(o.Clients))
	for _, c := range o.Clients {
		clients[c.ID] = c
	}
	return &Service{
		pool: o.Pool, hasher: o.Hasher, issuer: o.Issuer, tenants: o.Tenants,
		clients: clients, region: o.Region, totpKey: o.TOTPKey, limits: o.Limits,
	}
}

// NewUser describes an account to create.
type NewUser struct {
	Name        string
	Password    string
	DisplayName string
}

// CreateUser adds an active account inside tx.
func (s *Service) CreateUser(ctx context.Context, tx pgx.Tx, actor string, u NewUser) (string, error) {
	kind, value, err := NormalizeName(u.Name, s.region)
	if err != nil {
		return "", err
	}
	if err := checkPassword(u.Password, u.Name, value); err != nil {
		return "", err
	}
	displayName, err := cleanDisplayName(u.DisplayName)
	if err != nil {
		return "", err
	}
	hash, err := s.hasher.Hash(ctx, u.Password)
	if err != nil {
		return "", err
	}

	userID := ids.New("usr")
	if _, err := tx.Exec(ctx, "INSERT INTO auth.users (id, display_name) VALUES ($1, $2)", userID, displayName); err != nil {
		return "", fmt.Errorf("insert user: %w", err)
	}
	if err := insertName(ctx, tx, userID, kind, value); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO auth.credentials (user_id, password_hash) VALUES ($1, $2)", userID, hash); err != nil {
		return "", fmt.Errorf("insert credential: %w", err)
	}
	err = audit.Write(ctx, tx, audit.Entry{
		Actor: actor, Scope: audit.ScopePlatform, Action: "user.create", Target: userID, Outcome: audit.Success,
	})
	if err != nil {
		return "", err
	}
	return userID, nil
}

func insertName(ctx context.Context, tx pgx.Tx, userID, kind, value string) error {
	_, err := tx.Exec(ctx, "INSERT INTO auth.user_identifiers (kind, value, user_id) VALUES ($1, $2, $3)", kind, value, userID)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrNameTaken
	}
	if err != nil {
		return fmt.Errorf("insert identifier: %w", err)
	}
	return nil
}

type credential struct {
	userID, status, hash string
	lockedUntil          *time.Time
}

func (s *Service) lookupByName(ctx context.Context, name string) (credential, error) {
	kind, value, err := NormalizeName(name, s.region)
	if err != nil {
		return credential{}, err
	}
	var c credential
	err = s.pool.QueryRow(ctx,
		`SELECT u.id, u.status, c.password_hash, c.locked_until
		 FROM auth.user_identifiers i
		 JOIN auth.users u ON u.id = i.user_id
		 JOIN auth.credentials c ON c.user_id = u.id
		 WHERE i.kind = $1 AND i.value = $2`, kind, value).Scan(&c.userID, &c.status, &c.hash, &c.lockedUntil)
	return c, err
}

func (s *Service) lookupByID(ctx context.Context, userID string) (credential, error) {
	c := credential{userID: userID}
	err := s.pool.QueryRow(ctx,
		`SELECT u.status, c.password_hash, c.locked_until
		 FROM auth.users u JOIN auth.credentials c ON c.user_id = u.id
		 WHERE u.id = $1`, userID).Scan(&c.status, &c.hash, &c.lockedUntil)
	return c, err
}

// VerifyCredentials checks a sign-in. It reports whether a second factor was
// proved. Unknown names, wrong passwords, locked accounts and suspended users
// all return ErrInvalidCredentials; the audit log keeps the real reason.
func (s *Service) VerifyCredentials(ctx context.Context, name, password, code, ip string) (userID string, mfa bool, err error) {
	if err := s.allowIP(ctx, "signin:ip", ip, s.limits.SignInIP); err != nil {
		return "", false, err
	}
	if err := s.allowAccount(ctx, "signin:acct", name, s.limits.SignInAccount); err != nil {
		return "", false, err
	}

	c, err := s.lookupByName(ctx, name)
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrInvalidName) {
		s.hasher.VerifyDummy(ctx, password)
		s.deny(ctx, "anonymous", "", "unknown_name")
		return "", false, ErrInvalidCredentials
	}
	if err != nil {
		return "", false, err
	}
	mfa, err = s.checkSecrets(ctx, c, password, code)
	if err != nil {
		return "", false, err
	}
	return c.userID, mfa, nil
}

// checkSecrets applies lockout, password and any enrolled factor to c.
func (s *Service) checkSecrets(ctx context.Context, c credential, password, code string) (mfa bool, err error) {
	actor := audit.ActorUser(c.userID)
	if c.lockedUntil != nil && c.lockedUntil.After(time.Now()) {
		s.hasher.VerifyDummy(ctx, password)
		s.deny(ctx, actor, c.userID, "locked")
		return false, ErrInvalidCredentials
	}
	ok, err := s.hasher.Verify(ctx, password, c.hash)
	if err != nil {
		return false, err
	}
	if !ok {
		s.recordFailure(ctx, c.userID)
		s.deny(ctx, actor, c.userID, "wrong_password")
		return false, ErrInvalidCredentials
	}
	if c.status != "active" {
		s.deny(ctx, actor, c.userID, "user_"+c.status)
		return false, ErrInvalidCredentials
	}

	enrolled, err := s.hasTOTP(ctx, c.userID)
	if err != nil {
		return false, err
	}
	if enrolled {
		if code == "" {
			return false, ErrMFARequired
		}
		valid, err := s.verifyTOTP(ctx, c.userID, code)
		if err != nil {
			return false, err
		}
		if !valid {
			s.recordFailure(ctx, c.userID)
			s.deny(ctx, actor, c.userID, "wrong_totp")
			return false, ErrInvalidCredentials
		}
	}

	if err := s.clearFailures(ctx, c.userID); err != nil {
		return false, err
	}
	if s.hasher.NeedsRehash(c.hash) {
		s.rehash(ctx, c.userID, password)
	}
	return enrolled, nil
}

func (s *Service) clearFailures(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, "UPDATE auth.credentials SET failed_count = 0, locked_until = NULL WHERE user_id = $1", userID)
	if err != nil {
		return fmt.Errorf("clear failures: %w", err)
	}
	return nil
}

// recordFailure locks an account for a short, growing period after five
// failures. It is never permanent, which limits lockout attacks.
func (s *Service) recordFailure(ctx context.Context, userID string) {
	_, err := s.pool.Exec(context.WithoutCancel(ctx),
		`UPDATE auth.credentials SET
		   failed_count = failed_count + 1,
		   locked_until = CASE WHEN failed_count + 1 >= 5
		     THEN now() + make_interval(secs => LEAST(3600, 30 * power(2, LEAST(failed_count - 4, 10))))
		     ELSE locked_until END
		 WHERE user_id = $1`, userID)
	if err != nil {
		slog.ErrorContext(ctx, "record sign-in failure", "error", err)
	}
}

// rehash is best effort: the sign-in has succeeded either way.
func (s *Service) rehash(ctx context.Context, userID, password string) {
	hash, err := s.hasher.Hash(ctx, password)
	if err == nil {
		_, err = s.pool.Exec(ctx, "UPDATE auth.credentials SET password_hash = $2 WHERE user_id = $1", userID, hash)
	}
	if err != nil {
		slog.ErrorContext(ctx, "upgrade password hash", "error", err)
	}
}

// AccessToken is the result of a successful dev password login.
type AccessToken struct {
	Token     string
	ExpiresAt time.Time
}

// PasswordLogin signs a user in for the dev password grant. It goes through
// the same checks as a page sign-in, so an MFA account cannot use it to skip
// its second factor.
func (s *Service) PasswordLogin(ctx context.Context, name, password, tenant, ip string) (AccessToken, error) {
	userID, _, err := s.VerifyCredentials(ctx, name, password, "", ip)
	if errors.Is(err, ErrMFARequired) {
		return AccessToken{}, ErrInvalidCredentials
	}
	if err != nil {
		return AccessToken{}, err
	}

	tenantID, err := s.tenants.ResolveTenant(ctx, s.pool, userID, tenant)
	if err != nil {
		s.deny(ctx, audit.ActorUser(userID), userID, "tenant_refused")
		return AccessToken{}, err
	}

	sessionID := ids.New("ses")
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := time.Now()
		_, err := tx.Exec(ctx,
			`INSERT INTO auth.sessions (id, user_id, client_id, active_tenant_id, idle_expires_at, absolute_expires_at)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			sessionID, userID, devClientID, nullable(tenantID), now.Add(devIdleTTL), now.Add(devAbsoluteTTL))
		if err != nil {
			return fmt.Errorf("insert session: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "session.create",
			Target: sessionID, Outcome: audit.Success, Detail: map[string]any{"grant": "password", "tenant": tenantID},
		})
	})
	if err != nil {
		return AccessToken{}, err
	}

	token, expires, err := s.issuer.MintAccess(userID, tenantID, sessionID)
	if err != nil {
		return AccessToken{}, err
	}
	return AccessToken{Token: token, ExpiresAt: expires}, nil
}

func nullable(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// deny records a refused sign-in. It never records the submitted name, because
// people type passwords into that box.
func (s *Service) deny(ctx context.Context, actor, target, reason string) {
	err := audit.Write(context.WithoutCancel(ctx), s.pool, audit.Entry{
		Actor: actor, Scope: audit.ScopePlatform, Action: "session.create", Target: target,
		Outcome: audit.Denied, Detail: map[string]any{"reason": reason},
	})
	if err != nil {
		slog.ErrorContext(ctx, "audit write failed", "error", err)
	}
}

// Principal is the verified caller of a user endpoint or page.
type Principal struct {
	UserID    string
	TenantID  string
	SessionID string
	// MFA reports that this session proved a second factor.
	MFA bool
	// MFARecent reports that it did so within PlatformMFAWindow.
	MFARecent bool
	// DeviceID is set on a mobile app's session.
	DeviceID string
	// Service is set on an accessService route, where no user is involved.
	Service ServiceAccount
}

// Authenticate verifies a bearer token, then confirms its session and user are
// still live. Endpoints on this service can afford that database read, which
// offline verifiers elsewhere cannot.
func (s *Service) Authenticate(ctx context.Context, raw string) (Principal, error) {
	claims, err := s.issuer.Verify(raw)
	if err != nil {
		return Principal{}, err
	}
	if claims.SessionID == "" {
		return Principal{}, fmt.Errorf("%w: no session", ErrInvalidToken)
	}
	var mfaAt *time.Time
	var deviceID *string
	err = s.pool.QueryRow(ctx,
		`SELECT s.mfa_at, s.device_id FROM auth.sessions s
		 JOIN auth.users u ON u.id = s.user_id
		 LEFT JOIN auth.devices d ON d.id = s.device_id
		 WHERE s.id = $1 AND s.user_id = $2
		   AND u.status = 'active'
		   AND s.revoked_at IS NULL
		   AND d.revoked_at IS NULL
		   AND s.idle_expires_at > now()
		   AND (s.absolute_expires_at IS NULL OR s.absolute_expires_at > now())`,
		claims.SessionID, claims.Subject).Scan(&mfaAt, &deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, fmt.Errorf("%w: session ended", ErrInvalidToken)
	}
	if err != nil {
		return Principal{}, fmt.Errorf("check session: %w", err)
	}
	p := Principal{
		UserID: claims.Subject, TenantID: claims.TenantID, SessionID: claims.SessionID,
		MFA: mfaAt != nil, MFARecent: mfaAt != nil && time.Since(*mfaAt) < PlatformMFAWindow,
	}
	if deviceID != nil {
		p.DeviceID = *deviceID
	}
	return p, nil
}

// CreateBrowserSession starts a cookie session and returns the cookie value.
func (s *Service) CreateBrowserSession(ctx context.Context, userID string, mfa bool) (string, error) {
	sessionID := ids.New("ses")
	secret := randomSecret()
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := time.Now()
		var mfaAt *time.Time
		if mfa {
			mfaAt = &now
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO auth.sessions (id, user_id, client_id, secret_hash, idle_expires_at, absolute_expires_at, mfa_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			sessionID, userID, browserClientID, hashSecret(secret), now.Add(browserIdleTTL), now.Add(browserAbsoluteTTL), mfaAt)
		if err != nil {
			return fmt.Errorf("insert session: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "session.create",
			Target: sessionID, Outcome: audit.Success, Detail: map[string]any{"client": browserClientID, "mfa": mfa},
		})
	})
	if err != nil {
		return "", err
	}
	return sessionID + "." + secret, nil
}

// BrowserSession resolves a cookie and extends its idle limit, up to the
// absolute limit. Anything invalid returns ErrInvalidToken.
func (s *Service) BrowserSession(ctx context.Context, cookie string) (Principal, error) {
	sessionID, secret, ok := strings.Cut(cookie, ".")
	if !ok {
		return Principal{}, ErrInvalidToken
	}
	p := Principal{SessionID: sessionID}
	var mfaAt *time.Time
	err := s.pool.QueryRow(ctx,
		`UPDATE auth.sessions s
		 SET idle_expires_at = LEAST(now() + $3::interval, s.absolute_expires_at)
		 FROM auth.users u
		 WHERE u.id = s.user_id AND s.id = $1 AND s.secret_hash = $2 AND s.client_id = 'browser'
		   AND u.status = 'active' AND s.revoked_at IS NULL
		   AND s.idle_expires_at > now() AND s.absolute_expires_at > now()
		 RETURNING s.user_id, s.mfa_at`,
		sessionID, hashSecret(secret), fmt.Sprintf("%d seconds", int(browserIdleTTL.Seconds()))).Scan(&p.UserID, &mfaAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrInvalidToken
	}
	if err != nil {
		return Principal{}, fmt.Errorf("check browser session: %w", err)
	}
	p.MFA = mfaAt != nil
	p.MFARecent = mfaAt != nil && time.Since(*mfaAt) < PlatformMFAWindow
	return p, nil
}

// EndSession revokes one session.
func (s *Service) EndSession(ctx context.Context, userID, sessionID string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			"UPDATE auth.sessions SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL", sessionID, userID)
		if err != nil {
			return fmt.Errorf("revoke session: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "session.revoke",
			Target: sessionID, Outcome: audit.Success,
		})
	})
}

// revokeAccess ends all of a user's sessions but except, and every agent run of
// theirs. It's for sign-out everywhere, password changes and suspension, when
// the account may be in the wrong hands. A device sign-out leaves running calls alone.
func revokeAccess(ctx context.Context, tx pgx.Tx, userID, except string) error {
	if err := revokeSessions(ctx, tx, userID, except); err != nil {
		return err
	}
	return agents.RevokeUserGrants(ctx, tx, userID)
}

// revokeSessions ends all of a user's sessions but except.
func revokeSessions(ctx context.Context, tx pgx.Tx, userID, except string) error {
	_, err := tx.Exec(ctx,
		"UPDATE auth.sessions SET revoked_at = now() WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL", userID, except)
	if err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	return nil
}

// randomSecret returns 256 bits, URL-safe, with no dot so it can follow a
// session ID in a compound token.
func randomSecret() string {
	b := make([]byte, 32)
	rand.Read(b) // Never fails; see crypto/rand.
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}
