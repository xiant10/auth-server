package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/db"
	"t10-auth-server/internal/ids"
)

const (
	mfaChallengeTTL      = 5 * time.Minute
	mfaChallengeAttempts = 5
)

// DirectLogin is a POST /v1/login request.
type DirectLogin struct {
	ClientID, Name, Password, Tenant string
	Device                           DeviceInfo
	Challenge, Signature, IP         string
}

// DeviceTokens is a device session and its first access token. TenantID is
// empty when the user has several tenants and has not chosen one yet.
type DeviceTokens struct {
	Access    string
	ExpiresAt time.Time
	SessionID string
	DeviceID  string
	TenantID  string
}

// LoginResult is either tokens, or an MFAToken with a TOTP code still owed.
type LoginResult struct {
	Tokens   *DeviceTokens
	MFAToken string
}

func (s *Service) directClient(id string) (Client, error) {
	client, ok := s.Client(id)
	if !ok || !client.DirectLogin {
		return Client{}, ErrInvalidClient
	}
	return client, nil
}

// Login signs an app in with a password, enrolling its keys if they are new.
func (s *Service) Login(ctx context.Context, r DirectLogin) (LoginResult, error) {
	client, err := s.directClient(r.ClientID)
	if err != nil {
		return LoginResult{}, err
	}
	device, err := parseDevice(r.Device)
	if err != nil {
		return LoginResult{}, err
	}
	if err := s.verifyEnrollmentProof(ctx, PurposeLogin, device, r.Challenge, r.Signature); err != nil {
		return LoginResult{}, err
	}

	userID, mfa, err := s.VerifyCredentials(ctx, r.Name, r.Password, "", r.IP)
	if errors.Is(err, ErrMFARequired) {
		token, err := s.startMFAChallenge(ctx, client.ID, r)
		if err != nil {
			return LoginResult{}, err
		}
		return LoginResult{MFAToken: token}, nil
	}
	if err != nil {
		return LoginResult{}, err
	}
	tokens, err := s.completeDeviceLogin(ctx, deviceLogin{client: client, device: device, userID: userID, tenant: r.Tenant, mfa: mfa})
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Tokens: &tokens}, nil
}

func (s *Service) startMFAChallenge(ctx context.Context, clientID string, r DirectLogin) (string, error) {
	c, err := s.lookupByName(ctx, r.Name)
	if err != nil {
		return "", err
	}
	device, err := json.Marshal(r.Device)
	if err != nil {
		return "", fmt.Errorf("encode device: %w", err)
	}
	token := randomSecret()
	_, err = s.pool.Exec(ctx,
		`INSERT INTO auth.mfa_challenges (token_hash, user_id, client_id, device, tenant, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		hashSecret(token), c.userID, clientID, device, r.Tenant, time.Now().Add(mfaChallengeTTL))
	if err != nil {
		return "", fmt.Errorf("store MFA challenge: %w", err)
	}
	return token, nil
}

// CompleteMFA finishes a login with a TOTP code. A token allows a few attempts,
// each wrong code counts toward the account's lockout, and lockout stops tokens
// already issued, or collecting many would multiply the guesses.
func (s *Service) CompleteMFA(ctx context.Context, token, code string) (DeviceTokens, error) {
	var userID, clientID, tenant string
	var deviceJSON []byte
	err := s.pool.QueryRow(ctx,
		`UPDATE auth.mfa_challenges SET attempts = attempts + 1
		 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() AND attempts < $2
		 RETURNING user_id, client_id, device, tenant`,
		hashSecret(token), mfaChallengeAttempts).Scan(&userID, &clientID, &deviceJSON, &tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceTokens{}, ErrInvalidGrant
	}
	if err != nil {
		return DeviceTokens{}, fmt.Errorf("load MFA challenge: %w", err)
	}

	c, err := s.lookupByID(ctx, userID)
	if err != nil {
		return DeviceTokens{}, fmt.Errorf("load credential: %w", err)
	}
	if c.lockedUntil != nil && c.lockedUntil.After(time.Now()) {
		s.deny(ctx, audit.ActorUser(userID), userID, "locked")
		return DeviceTokens{}, ErrInvalidCredentials
	}
	valid, err := s.verifyTOTP(ctx, userID, code)
	if err != nil {
		return DeviceTokens{}, err
	}
	if !valid {
		s.recordFailure(ctx, userID)
		s.deny(ctx, audit.ActorUser(userID), userID, "wrong_totp")
		return DeviceTokens{}, ErrInvalidCredentials
	}
	if err := s.clearFailures(ctx, userID); err != nil {
		return DeviceTokens{}, err
	}
	tag, err := s.pool.Exec(ctx,
		"UPDATE auth.mfa_challenges SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL", hashSecret(token))
	if err != nil {
		return DeviceTokens{}, fmt.Errorf("spend MFA challenge: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return DeviceTokens{}, ErrInvalidGrant
	}

	client, err := s.directClient(clientID)
	if err != nil {
		return DeviceTokens{}, err
	}
	var info DeviceInfo
	if err := json.Unmarshal(deviceJSON, &info); err != nil {
		return DeviceTokens{}, fmt.Errorf("decode device: %w", err)
	}
	device, err := parseDevice(info)
	if err != nil {
		return DeviceTokens{}, err
	}
	return s.completeDeviceLogin(ctx, deviceLogin{client: client, device: device, userID: userID, tenant: tenant, mfa: true})
}

// VerifyDeviceSignup checks an in-app registration's client, keys and proof,
// before any account exists.
func (s *Service) VerifyDeviceSignup(ctx context.Context, clientID string, info DeviceInfo, challenge, signature string) error {
	if _, err := s.directClient(clientID); err != nil {
		return err
	}
	device, err := parseDevice(info)
	if err != nil {
		return err
	}
	return s.verifyEnrollmentProof(ctx, PurposeRegister, device, challenge, signature)
}

// EnrollFirstDevice starts the session of a just-registered account.
func (s *Service) EnrollFirstDevice(ctx context.Context, clientID, userID string, info DeviceInfo) (DeviceTokens, error) {
	client, err := s.directClient(clientID)
	if err != nil {
		return DeviceTokens{}, err
	}
	device, err := parseDevice(info)
	if err != nil {
		return DeviceTokens{}, err
	}
	return s.completeDeviceLogin(ctx, deviceLogin{client: client, device: device, userID: userID, firstDevice: true})
}

type deviceLogin struct {
	client Client
	device parsedDevice
	userID string
	tenant string
	// mfa means a second factor was proved during this login.
	mfa bool
	// approved means an enrolled device approved this one.
	approved bool
	// firstDevice means this account was created just now. If its tenant
	// requires a factor it gets a session with no tenant, so it can receive its
	// recovery codes and enroll one.
	firstDevice bool
}

// completeDeviceLogin finds or enrolls the device and starts its session.
// Known keys return to their device row, which is how an app signs back in
// after a password reset ended its session. A new device on an account that
// already has one needs an approval or a second factor.
func (s *Service) completeDeviceLogin(ctx context.Context, l deviceLogin) (DeviceTokens, error) {
	var tokens DeviceTokens
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Serializes enrollments, so two can't both see an empty device list. It
		// also rechecks the user, who may have changed since the password check.
		var status string
		if err := tx.QueryRow(ctx, "SELECT status FROM auth.users WHERE id = $1 FOR UPDATE", l.userID).Scan(&status); err != nil {
			return fmt.Errorf("lock user: %w", err)
		}
		if status != "active" {
			return ErrInvalidCredentials
		}
		var deviceID, owner string
		var capable bool
		var revoked *time.Time
		err := tx.QueryRow(ctx,
			"SELECT id, user_id, mfa_capable, revoked_at FROM auth.devices WHERE session_public_key = $1",
			l.device.session).Scan(&deviceID, &owner, &capable, &revoked)
		switch {
		case err == nil:
			if owner != l.userID {
				return ErrInvalidDevice
			}
			if revoked != nil {
				return ErrDeviceRevoked
			}
		case errors.Is(err, pgx.ErrNoRows):
			if deviceID, capable, err = enrollDevice(ctx, tx, l); err != nil {
				return err
			}
		default:
			return fmt.Errorf("load device: %w", err)
		}

		// Password plus a key enrolled with a factor is itself two factors.
		mfa := l.mfa || capable
		tenantID, err := s.deviceTenant(ctx, tx, l.userID, l.tenant, mfa)
		if l.firstDevice && errors.Is(err, ErrMFARequired) {
			tenantID, err = "", nil
		}
		if err != nil {
			return err
		}
		var mfaAt, absolute *time.Time
		now := time.Now()
		if mfa {
			mfaAt = &now
		}
		if l.client.AbsoluteTTL > 0 {
			limit := now.Add(l.client.AbsoluteTTL)
			absolute = &limit
		}
		sessionID := ids.New("ses")
		_, err = tx.Exec(ctx,
			`INSERT INTO auth.sessions (id, user_id, client_id, device_id, active_tenant_id, idle_expires_at, absolute_expires_at, mfa_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			sessionID, l.userID, l.client.ID, deviceID, nullable(tenantID), now.Add(l.client.IdleTTL), absolute, mfaAt)
		if err != nil {
			return fmt.Errorf("insert session: %w", err)
		}
		err = audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(l.userID), Scope: audit.ScopePlatform, Action: "session.create", Target: sessionID,
			Outcome: audit.Success, Detail: map[string]any{"client": l.client.ID, "device": deviceID, "mfa": mfa},
		})
		if err != nil {
			return err
		}
		access, expires, err := s.issuer.MintAccess(l.userID, tenantID, sessionID)
		if err != nil {
			return err
		}
		tokens = DeviceTokens{Access: access, ExpiresAt: expires, SessionID: sessionID, DeviceID: deviceID, TenantID: tenantID}
		return nil
	})
	return tokens, err
}

func enrollDevice(ctx context.Context, tx pgx.Tx, l deviceLogin) (string, bool, error) {
	var active int
	err := tx.QueryRow(ctx, "SELECT count(*) FROM auth.devices WHERE user_id = $1 AND revoked_at IS NULL", l.userID).Scan(&active)
	if err != nil {
		return "", false, fmt.Errorf("count devices: %w", err)
	}
	if active > 0 && !l.mfa && !l.approved {
		return "", false, ErrDeviceApprovalRequired
	}
	deviceID := ids.New("dev")
	_, err = tx.Exec(ctx,
		`INSERT INTO auth.devices (id, user_id, name, platform, approval_public_key, session_public_key, mfa_capable, last_used_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, now())`,
		deviceID, l.userID, l.device.name, l.device.platform, l.device.approval, l.device.session, l.mfa)
	if err != nil {
		return "", false, fmt.Errorf("insert device: %w", err)
	}
	err = audit.Write(ctx, tx, audit.Entry{
		Actor: audit.ActorUser(l.userID), Scope: audit.ScopePlatform, Action: "device.enroll", Target: deviceID,
		Outcome: audit.Success, Detail: map[string]any{"platform": l.device.platform, "mfa_capable": l.mfa, "approved": l.approved},
	})
	if err != nil {
		return "", false, err
	}
	return deviceID, l.mfa, nil
}

// deviceTenant is tenantFor, except that having several tenants is not an
// error: an app gets a token with no tenant, lists them, and picks one with a
// refresh. Such a token opens nothing that needs a tenant.
func (s *Service) deviceTenant(ctx context.Context, q db.Querier, userID, requested string, mfa bool) (string, error) {
	tenantID, err := s.tenantFor(ctx, q, userID, requested, mfa)
	if s.tenants.IsTenantRequired(err) {
		return "", nil
	}
	return tenantID, err
}

// DeviceRefresh is a grant_type=device_refresh request.
type DeviceRefresh struct {
	ClientID, SessionID, Challenge, Signature, Tenant string
}

// RefreshDevice mints a new access token for a signature by the device's silent
// session key. Nothing rotates, so a lost response costs only a retry. Each
// refresh extends the idle limit and rechecks the user, device and membership.
func (s *Service) RefreshDevice(ctx context.Context, r DeviceRefresh) (DeviceTokens, error) {
	client, err := s.directClient(r.ClientID)
	if err != nil {
		return DeviceTokens{}, err
	}
	var userID, deviceID, status string
	var tenant *string
	var sessionKey []byte
	var mfaAt, idle *time.Time
	var absolute, sessionRevoked, deviceRevoked *time.Time
	err = s.pool.QueryRow(ctx,
		`SELECT s.user_id, s.device_id, u.status, s.active_tenant_id, d.session_public_key, s.mfa_at,
		        s.idle_expires_at, s.absolute_expires_at, s.revoked_at, d.revoked_at
		 FROM auth.sessions s
		 JOIN auth.users u ON u.id = s.user_id
		 JOIN auth.devices d ON d.id = s.device_id
		 WHERE s.id = $1 AND s.client_id = $2`, r.SessionID, client.ID).
		Scan(&userID, &deviceID, &status, &tenant, &sessionKey, &mfaAt, &idle, &absolute, &sessionRevoked, &deviceRevoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceTokens{}, ErrInvalidGrant
	}
	if err != nil {
		return DeviceTokens{}, fmt.Errorf("load device session: %w", err)
	}
	if err := s.consumeChallenge(ctx, PurposeRefresh, r.Challenge); err != nil {
		return DeviceTokens{}, err
	}
	if !verifySignature(sessionKey, SignedMessage(PurposeRefresh, r.Challenge, r.SessionID), r.Signature) {
		return DeviceTokens{}, ErrInvalidDevice
	}

	now := time.Now()
	if sessionRevoked != nil || deviceRevoked != nil || status != "active" || !idle.After(now) || (absolute != nil && !absolute.After(now)) {
		return DeviceTokens{}, ErrInvalidGrant
	}
	requested := r.Tenant
	if requested == "" && tenant != nil {
		requested = *tenant
	}
	tenantID, err := s.deviceTenant(ctx, s.pool, userID, requested, mfaAt != nil)
	if err != nil {
		return DeviceTokens{}, err
	}

	nextIdle := now.Add(client.IdleTTL)
	if absolute != nil && absolute.Before(nextIdle) {
		nextIdle = *absolute
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			"UPDATE auth.sessions SET idle_expires_at = $2, active_tenant_id = $3 WHERE id = $1 AND revoked_at IS NULL",
			r.SessionID, nextIdle, nullable(tenantID))
		if err != nil {
			return fmt.Errorf("extend session: %w", err)
		}
		_, err = tx.Exec(ctx, "UPDATE auth.devices SET last_used_at = now() WHERE id = $1", deviceID)
		return err
	})
	if err != nil {
		return DeviceTokens{}, err
	}
	access, expires, err := s.issuer.MintAccess(userID, tenantID, r.SessionID)
	if err != nil {
		return DeviceTokens{}, err
	}
	return DeviceTokens{Access: access, ExpiresAt: expires, SessionID: r.SessionID, DeviceID: deviceID, TenantID: tenantID}, nil
}

// RevokeDevice ends a device's approval rights and all its sessions. A key it
// held can never enroll again.
func (s *Service) RevokeDevice(ctx context.Context, userID, deviceID string, r Reauth) error {
	if err := s.checkReauth(ctx, userID, "device_revoke:"+deviceID, r); err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			"UPDATE auth.devices SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL", deviceID, userID)
		if err != nil {
			return fmt.Errorf("revoke device: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrDeviceRevoked
		}
		if _, err := tx.Exec(ctx, "UPDATE auth.sessions SET revoked_at = now() WHERE device_id = $1 AND revoked_at IS NULL", deviceID); err != nil {
			return fmt.Errorf("revoke device sessions: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "device.revoke", Target: deviceID, Outcome: audit.Success,
		})
	})
}
