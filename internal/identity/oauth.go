package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"t10-auth-server/internal/agents"
	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/db"
	"t10-auth-server/internal/ids"
)

const (
	authCodeTTL = 60 * time.Second
	// maxRetiredSecrets bounds the replay history kept on a session row.
	maxRetiredSecrets = 32
)

// OAuth errors.
var (
	ErrInvalidGrant  = errors.New("invalid grant")
	ErrInvalidClient = errors.New("invalid client")
)

// Client finds a configured client.
func (s *Service) Client(id string) (Client, bool) {
	c, ok := s.clients[id]
	return c, ok
}

// IssueCode creates a 60-second, single-use code for a signed-in browser.
func (s *Service) IssueCode(ctx context.Context, sessionID, clientID, redirectURI, challenge string) (string, error) {
	code := randomSecret()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO auth.auth_codes (code_hash, session_id, client_id, code_challenge, redirect_uri, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		hashSecret(code), sessionID, clientID, challenge, redirectURI, time.Now().Add(authCodeTTL))
	if err != nil {
		return "", fmt.Errorf("store code: %w", err)
	}
	return code, nil
}

// Redemption is a grant_type=authorization_code request.
type Redemption struct {
	Code, ClientID, ClientSecret, RedirectURI, Verifier, Tenant string
}

// Tokens is the result of a code redemption or refresh.
type Tokens struct {
	Access    string
	ExpiresAt time.Time
	// Refresh is the session ID and secret, joined for the client to store.
	Refresh string
}

func (s *Service) authenticateClient(id, secret string) (Client, error) {
	client, ok := s.Client(id)
	if !ok || !client.checkSecret(secret) {
		return Client{}, ErrInvalidClient
	}
	return client, nil
}

// RedeemCode exchanges a code for a new session belonging to the client. The
// browser session stays separate, so each keeps its own lifetime and signing
// out of one leaves the other. A refused redemption rolls back and leaves the
// code unspent; a replayed code revokes the session it already produced.
func (s *Service) RedeemCode(ctx context.Context, r Redemption) (Tokens, error) {
	client, err := s.authenticateClient(r.ClientID, r.ClientSecret)
	if err != nil {
		return Tokens{}, err
	}

	var replayed string
	var tokens Tokens
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var browserSession, clientID, challenge, redirectURI string
		var expires time.Time
		var used *time.Time
		var issued *string
		err := tx.QueryRow(ctx,
			`SELECT session_id, client_id, code_challenge, redirect_uri, expires_at, used_at, issued_session_id
			 FROM auth.auth_codes WHERE code_hash = $1 FOR UPDATE`, hashSecret(r.Code)).
			Scan(&browserSession, &clientID, &challenge, &redirectURI, &expires, &used, &issued)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidGrant
		}
		if err != nil {
			return fmt.Errorf("load code: %w", err)
		}
		if used != nil {
			if issued != nil {
				replayed = *issued
				_, err := tx.Exec(ctx, "UPDATE auth.sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL", *issued)
				return err
			}
			return ErrInvalidGrant
		}
		if !expires.After(time.Now()) || clientID != r.ClientID || redirectURI != r.RedirectURI || !checkPKCE(r.Verifier, challenge) {
			return ErrInvalidGrant
		}

		var userID string
		var mfaAt *time.Time
		err = tx.QueryRow(ctx,
			`SELECT s.user_id, s.mfa_at FROM auth.sessions s
			 JOIN auth.users u ON u.id = s.user_id
			 WHERE s.id = $1 AND s.revoked_at IS NULL AND s.idle_expires_at > now() AND u.status = 'active'`,
			browserSession).Scan(&userID, &mfaAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidGrant
		}
		if err != nil {
			return fmt.Errorf("load browser session: %w", err)
		}

		tenantID, err := s.tenantFor(ctx, tx, userID, r.Tenant, mfaAt != nil)
		if err != nil {
			return err
		}
		sessionID, refresh, err := insertClientSession(ctx, tx, client, userID, tenantID, mfaAt)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE auth.auth_codes SET used_at = now(), issued_session_id = $2 WHERE code_hash = $1",
			hashSecret(r.Code), sessionID); err != nil {
			return fmt.Errorf("spend code: %w", err)
		}
		access, expiresAt, err := s.issuer.MintAccess(userID, tenantID, sessionID)
		if err != nil {
			return err
		}
		tokens = Tokens{Access: access, ExpiresAt: expiresAt, Refresh: refresh}
		return nil
	})
	if err != nil {
		return Tokens{}, err
	}
	if replayed != "" {
		s.denyReplay(ctx, "code_replay", replayed)
		return Tokens{}, ErrInvalidGrant
	}
	return tokens, nil
}

func (s *Service) tenantFor(ctx context.Context, q db.Querier, userID, requested string, mfa bool) (string, error) {
	tenantID, err := s.tenants.ResolveTenant(ctx, q, userID, requested)
	if err != nil || tenantID == "" {
		return tenantID, err
	}
	required, err := s.tenants.TenantRequiresMFA(ctx, q, tenantID)
	if err != nil {
		return "", err
	}
	if required && !mfa {
		return "", ErrMFARequired
	}
	return tenantID, nil
}

func insertClientSession(ctx context.Context, tx pgx.Tx, client Client, userID, tenantID string, mfaAt *time.Time) (sessionID, refresh string, err error) {
	sessionID = ids.New("ses")
	secret := randomSecret()
	now := time.Now()
	var absolute *time.Time
	idle := now.Add(client.IdleTTL)
	if client.AbsoluteTTL > 0 {
		limit := now.Add(client.AbsoluteTTL)
		absolute = &limit
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO auth.sessions (id, user_id, client_id, active_tenant_id, secret_hash, idle_expires_at, absolute_expires_at, mfa_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		sessionID, userID, client.ID, nullable(tenantID), hashSecret(secret), idle, absolute, mfaAt)
	if err != nil {
		return "", "", fmt.Errorf("insert session: %w", err)
	}
	err = audit.Write(ctx, tx, audit.Entry{
		Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "session.create", Target: sessionID,
		Outcome: audit.Success, Detail: map[string]any{"client": client.ID, "tenant": tenantID},
	})
	if err != nil {
		return "", "", err
	}
	return sessionID, sessionID + "." + secret, nil
}

// checkPKCE compares the S256 hash of the verifier with the challenge.
func checkPKCE(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

// Refreshing is a grant_type=refresh_token request.
type Refreshing struct {
	Refresh, ClientID, ClientSecret, Tenant string
}

type sessionRow struct {
	userID, clientID, status string
	tenantID                 *string
	current, previous        []byte
	retired                  [][]byte
	idle                     time.Time
	absolute, revoked, mfaAt *time.Time
}

func loadSession(ctx context.Context, tx pgx.Tx, sessionID string) (sessionRow, error) {
	var r sessionRow
	err := tx.QueryRow(ctx,
		`SELECT s.user_id, s.client_id, u.status, s.active_tenant_id, s.secret_hash, s.prev_secret_hash,
		        s.retired_secret_hashes, s.idle_expires_at, s.absolute_expires_at, s.revoked_at, s.mfa_at
		 FROM auth.sessions s JOIN auth.users u ON u.id = s.user_id
		 WHERE s.id = $1 FOR UPDATE OF s`, sessionID).
		Scan(&r.userID, &r.clientID, &r.status, &r.tenantID, &r.current, &r.previous,
			&r.retired, &r.idle, &r.absolute, &r.revoked, &r.mfaAt)
	return r, err
}

func (r sessionRow) expired(now time.Time) bool {
	return r.revoked != nil || !r.idle.After(now) || (r.absolute != nil && !r.absolute.After(now))
}

// Refresh rotates a session's secret and mints a new access token. The previous
// secret stays valid until the new one is first used, so a lost response cannot
// sign the user out. Any secret spent before that is a replay, and revokes the
// session. Every refresh rechecks the user and membership.
func (s *Service) Refresh(ctx context.Context, r Refreshing) (Tokens, error) {
	client, err := s.authenticateClient(r.ClientID, r.ClientSecret)
	if err != nil {
		return Tokens{}, err
	}
	sessionID, secret, ok := strings.Cut(r.Refresh, ".")
	if !ok {
		return Tokens{}, ErrInvalidGrant
	}

	presented := hashSecret(secret)
	replay := false
	var tokens Tokens
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		row, err := loadSession(ctx, tx, sessionID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidGrant
		}
		if err != nil {
			return fmt.Errorf("load session: %w", err)
		}
		now := time.Now()
		if row.clientID != client.ID || row.expired(now) || row.current == nil || row.status != "active" {
			return ErrInvalidGrant
		}

		retired := row.retired
		previous := row.previous
		switch {
		case subtle.ConstantTimeCompare(presented, row.current) == 1:
			// The newest secret is in use, so the one before it is now spent.
			if previous != nil {
				retired = append(retired, previous)
			}
			previous = row.current
		case previous != nil && subtle.ConstantTimeCompare(presented, previous) == 1:
			// The last response was lost; its unused secret is abandoned.
			retired = append(retired, row.current)
		case slices.ContainsFunc(retired, func(h []byte) bool { return subtle.ConstantTimeCompare(presented, h) == 1 }):
			replay = true
			_, err := tx.Exec(ctx, "UPDATE auth.sessions SET revoked_at = now() WHERE id = $1", sessionID)
			return err
		default:
			return ErrInvalidGrant
		}
		if len(retired) > maxRetiredSecrets {
			retired = retired[len(retired)-maxRetiredSecrets:]
		}

		requested := r.Tenant
		if requested == "" && row.tenantID != nil {
			requested = *row.tenantID
		}
		tenantID, err := s.tenantFor(ctx, tx, row.userID, requested, row.mfaAt != nil)
		if err != nil {
			return err
		}

		next := randomSecret()
		idle := now.Add(client.IdleTTL)
		if row.absolute != nil && row.absolute.Before(idle) {
			idle = *row.absolute
		}
		_, err = tx.Exec(ctx,
			`UPDATE auth.sessions
			 SET secret_hash = $2, prev_secret_hash = $3, retired_secret_hashes = $4, idle_expires_at = $5, active_tenant_id = $6
			 WHERE id = $1`,
			sessionID, hashSecret(next), previous, retired, idle, nullable(tenantID))
		if err != nil {
			return fmt.Errorf("rotate session: %w", err)
		}
		// Using t10 keeps a person's consent to their automations.
		if err := agents.RenewStanding(ctx, tx, row.userID); err != nil {
			return err
		}
		access, expires, err := s.issuer.MintAccess(row.userID, tenantID, sessionID)
		if err != nil {
			return err
		}
		tokens = Tokens{Access: access, ExpiresAt: expires, Refresh: sessionID + "." + next}
		return nil
	})
	if err != nil {
		return Tokens{}, err
	}
	if replay {
		s.denyReplay(ctx, "secret_replay", sessionID)
		return Tokens{}, ErrInvalidGrant
	}
	return tokens, nil
}

// RevokeRefresh ends the session a refresh token belongs to. It reports nothing
// about tokens it does not recognize.
func (s *Service) RevokeRefresh(ctx context.Context, clientID, clientSecret, refresh string) error {
	client, err := s.authenticateClient(clientID, clientSecret)
	if err != nil {
		return err
	}
	sessionID, secret, ok := strings.Cut(refresh, ".")
	if !ok {
		return nil
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		row, err := loadSession(ctx, tx, sessionID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("load session: %w", err)
		}
		presented := hashSecret(secret)
		if row.clientID != client.ID ||
			(subtle.ConstantTimeCompare(presented, row.current) != 1 && subtle.ConstantTimeCompare(presented, row.previous) != 1) {
			return nil
		}
		if _, err := tx.Exec(ctx, "UPDATE auth.sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL", sessionID); err != nil {
			return fmt.Errorf("revoke session: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(row.userID), Scope: audit.ScopePlatform, Action: "session.revoke", Target: sessionID, Outcome: audit.Success,
		})
	})
}

func (s *Service) denyReplay(ctx context.Context, reason, sessionID string) {
	err := audit.Write(context.WithoutCancel(ctx), s.pool, audit.Entry{
		Actor: "anonymous", Scope: audit.ScopePlatform, Action: "session.refresh", Target: sessionID,
		Outcome: audit.Denied, Detail: map[string]any{"reason": reason},
	})
	if err != nil {
		slog.ErrorContext(ctx, "audit write failed", "error", err)
	}
}
