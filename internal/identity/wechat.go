package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/ids"
)

var (
	// ErrWeChatUnavailable means this deployment has no mini-program, or WeChat can't
	// be reached. Retrying later may work.
	ErrWeChatUnavailable = errors.New("wechat unavailable")
	// ErrWeChatCode means WeChat refused the one-time code. Get a new one.
	ErrWeChatCode = errors.New("wechat code refused")
	// ErrWeChatBound means this WeChat identity or this account is already bound to the other.
	ErrWeChatBound = errors.New("wechat binding conflict")
)

// WeChatIdentity turns a mini-program's one-time login code into who the person is.
type WeChatIdentity interface {
	OpenID(ctx context.Context, code string) (string, error)
}

// WeChatAPI is WeChat's code exchange. Its URL holds the app secret, so no error from
// here may include the URL.
type WeChatAPI struct {
	AppID, Secret, BaseURL string
	HTTP                   *http.Client
}

// OpenID asks WeChat who a code belongs to.
func (w WeChatAPI) OpenID(ctx context.Context, code string) (string, error) {
	query := url.Values{"appid": {w.AppID}, "secret": {w.Secret}, "js_code": {code}, "grant_type": {"authorization_code"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.BaseURL+"/sns/jscode2session?"+query.Encode(), nil)
	if err != nil {
		return "", fmt.Errorf("%w: bad request", ErrWeChatUnavailable)
	}
	res, err := w.HTTP.Do(req)
	if err != nil {
		var failure *url.Error
		if errors.As(err, &failure) {
			err = failure.Err
		}
		return "", fmt.Errorf("%w: %v", ErrWeChatUnavailable, err)
	}
	defer res.Body.Close()
	var out struct {
		OpenID  string `json:"openid"`
		ErrCode int    `json:"errcode"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<16)).Decode(&out); err != nil {
		return "", fmt.Errorf("%w: unreadable answer", ErrWeChatUnavailable)
	}
	switch {
	case out.ErrCode == 0 && out.OpenID != "":
		return out.OpenID, nil
	// Invalid, and already used.
	case out.ErrCode == 40029 || out.ErrCode == 40163:
		return "", ErrWeChatCode
	default:
		return "", fmt.Errorf("%w: errcode %d", ErrWeChatUnavailable, out.ErrCode)
	}
}

// WeChatSignIn is a person signing in on a mini-program. Only this creates a session, so
// an idle session always comes back to the password.
type WeChatSignIn struct {
	ClientID, Code, Name, Password, TOTP, Tenant, IP string
}

// WeChatRefresh mints a token for a session. A new code proves it's still that WeChat
// identity, so nothing long-lived is stored on the phone.
type WeChatRefresh struct {
	ClientID, SessionID, Code, Tenant, IP string
}

// UseWeChat connects a mini-program. Without it, the WeChat routes refuse.
func (s *Service) UseWeChat(identity WeChatIdentity, appID string) {
	s.wechat, s.wechatApp = identity, appID
}

func (s *Service) wechatClient(id string) (Client, error) {
	client, ok := s.Client(id)
	if !ok || !client.WeChat {
		return Client{}, ErrInvalidClient
	}
	if s.wechat == nil {
		return Client{}, ErrWeChatUnavailable
	}
	return client, nil
}

// SignInWeChat checks the password before spending WeChat's code, binds the identity to
// the account the first time, and starts a session.
func (s *Service) SignInWeChat(ctx context.Context, r WeChatSignIn) (DeviceTokens, error) {
	client, err := s.wechatClient(r.ClientID)
	if err != nil {
		return DeviceTokens{}, err
	}
	userID, mfa, err := s.VerifyCredentials(ctx, r.Name, r.Password, r.TOTP, r.IP)
	if err != nil {
		return DeviceTokens{}, err
	}
	openID, err := s.wechat.OpenID(ctx, r.Code)
	if err != nil {
		return DeviceTokens{}, err
	}
	var tokens DeviceTokens
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if client.WeChatDemo {
			if err := s.unbindForDemo(ctx, tx, openID, userID); err != nil {
				return err
			}
		}
		if err := s.bindWeChat(ctx, tx, openID, userID); err != nil {
			return err
		}
		tenantID, err := s.deviceTenant(ctx, tx, userID, r.Tenant, mfa)
		if err != nil {
			return err
		}
		now := time.Now()
		var mfaAt, absolute *time.Time
		if mfa {
			mfaAt = &now
		}
		if client.AbsoluteTTL > 0 {
			limit := now.Add(client.AbsoluteTTL)
			absolute = &limit
		}
		sessionID := ids.New("ses")
		_, err = tx.Exec(ctx,
			`INSERT INTO auth.sessions (id, user_id, client_id, active_tenant_id, idle_expires_at, absolute_expires_at, mfa_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			sessionID, userID, client.ID, nullable(tenantID), now.Add(client.IdleTTL), absolute, mfaAt)
		if err != nil {
			return fmt.Errorf("insert session: %w", err)
		}
		err = audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "session.create", Target: sessionID,
			Outcome: audit.Success, Detail: map[string]any{"client": client.ID, "mfa": mfa},
		})
		if err != nil {
			return err
		}
		access, expires, err := s.issuer.MintAccess(userID, tenantID, sessionID)
		if err != nil {
			return err
		}
		tokens = DeviceTokens{Access: access, ExpiresAt: expires, SessionID: sessionID, TenantID: tenantID}
		return nil
	})
	return tokens, err
}

// bindWeChat holds one identity to one account, in both directions.
func (s *Service) bindWeChat(ctx context.Context, tx pgx.Tx, openID, userID string) error {
	var boundUser, boundOpenID string
	err := tx.QueryRow(ctx,
		`SELECT user_id, openid FROM auth.wechat_bindings
		 WHERE app_id = $1 AND removed_at IS NULL AND (openid = $2 OR user_id = $3)
		 ORDER BY openid = $2 DESC LIMIT 1`, s.wechatApp, openID, userID).Scan(&boundUser, &boundOpenID)
	switch {
	case err == nil && boundUser == userID && boundOpenID == openID:
		return nil
	case err == nil:
		return ErrWeChatBound
	case !errors.Is(err, pgx.ErrNoRows):
		return fmt.Errorf("load wechat binding: %w", err)
	}
	id := ids.New("wxb")
	_, err = tx.Exec(ctx, `INSERT INTO auth.wechat_bindings (id, app_id, openid, user_id) VALUES ($1, $2, $3, $4)`, id, s.wechatApp, openID, userID)
	var conflict *pgconn.PgError
	if errors.As(err, &conflict) && conflict.Code == "23505" {
		return ErrWeChatBound
	}
	if err != nil {
		return fmt.Errorf("insert wechat binding: %w", err)
	}
	return audit.Write(ctx, tx, audit.Entry{
		Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "wechat.bind", Target: id, Outcome: audit.Success,
	})
}

// unbindForDemo removes whatever holds this identity or this account to another, so
// bindWeChat can bind the two. The rows stay, as a removed binding does.
func (s *Service) unbindForDemo(ctx context.Context, tx pgx.Tx, openID, userID string) error {
	rows, err := tx.Query(ctx,
		`UPDATE auth.wechat_bindings SET removed_at = now()
		 WHERE app_id = $1 AND removed_at IS NULL AND (openid = $2) <> (user_id = $3)
		 RETURNING id, user_id`, s.wechatApp, openID, userID)
	if err != nil {
		return fmt.Errorf("move wechat binding: %w", err)
	}
	type moved struct{ id, user string }
	var all []moved
	for rows.Next() {
		var m moved
		if err := rows.Scan(&m.id, &m.user); err != nil {
			rows.Close()
			return fmt.Errorf("move wechat binding: %w", err)
		}
		all = append(all, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("move wechat binding: %w", err)
	}
	for _, m := range all {
		err := audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "wechat.unbind", Target: m.id, Outcome: audit.Success,
			Detail: map[string]any{"demo": true, "user": m.user},
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// wechatSession loads a session and checks the code against its binding. Anything wrong
// answers the same, so a stranger learns nothing about a session ID.
func (s *Service) wechatSession(ctx context.Context, clientID, sessionID, code string) (userID string, tenant *string, mfa bool, absolute *time.Time, err error) {
	var status string
	var mfaAt, idle, revoked *time.Time
	err = s.pool.QueryRow(ctx,
		`SELECT s.user_id, u.status, s.active_tenant_id, s.mfa_at, s.idle_expires_at, s.absolute_expires_at, s.revoked_at
		 FROM auth.sessions s JOIN auth.users u ON u.id = s.user_id
		 WHERE s.id = $1 AND s.client_id = $2`, sessionID, clientID).
		Scan(&userID, &status, &tenant, &mfaAt, &idle, &absolute, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, false, nil, ErrInvalidGrant
	}
	if err != nil {
		return "", nil, false, nil, fmt.Errorf("load wechat session: %w", err)
	}
	now := time.Now()
	if revoked != nil || status != "active" || !idle.After(now) || (absolute != nil && !absolute.After(now)) {
		return "", nil, false, nil, ErrInvalidGrant
	}
	openID, err := s.wechat.OpenID(ctx, code)
	if err != nil {
		return "", nil, false, nil, err
	}
	var bound int
	err = s.pool.QueryRow(ctx,
		`SELECT count(*) FROM auth.wechat_bindings WHERE app_id = $1 AND openid = $2 AND user_id = $3 AND removed_at IS NULL`,
		s.wechatApp, openID, userID).Scan(&bound)
	if err != nil {
		return "", nil, false, nil, fmt.Errorf("check wechat binding: %w", err)
	}
	if bound == 0 {
		return "", nil, false, nil, ErrInvalidGrant
	}
	return userID, tenant, mfaAt != nil, absolute, nil
}

// RefreshWeChat mints a token for a live session, and extends its idle limit.
func (s *Service) RefreshWeChat(ctx context.Context, r WeChatRefresh) (DeviceTokens, error) {
	client, err := s.wechatClient(r.ClientID)
	if err != nil {
		return DeviceTokens{}, err
	}
	if err := s.allowIP(ctx, "wechat:ip", r.IP, s.limits.SignInIP); err != nil {
		return DeviceTokens{}, err
	}
	userID, tenant, mfa, absolute, err := s.wechatSession(ctx, client.ID, r.SessionID, r.Code)
	if err != nil {
		return DeviceTokens{}, err
	}
	requested := r.Tenant
	if requested == "" && tenant != nil {
		requested = *tenant
	}
	tenantID, err := s.deviceTenant(ctx, s.pool, userID, requested, mfa)
	if err != nil {
		return DeviceTokens{}, err
	}
	nextIdle := time.Now().Add(client.IdleTTL)
	if absolute != nil && absolute.Before(nextIdle) {
		nextIdle = *absolute
	}
	_, err = s.pool.Exec(ctx, "UPDATE auth.sessions SET idle_expires_at = $2, active_tenant_id = $3 WHERE id = $1 AND revoked_at IS NULL", r.SessionID, nextIdle, nullable(tenantID))
	if err != nil {
		return DeviceTokens{}, fmt.Errorf("extend session: %w", err)
	}
	access, expires, err := s.issuer.MintAccess(userID, tenantID, r.SessionID)
	if err != nil {
		return DeviceTokens{}, err
	}
	return DeviceTokens{Access: access, ExpiresAt: expires, SessionID: r.SessionID, TenantID: tenantID}, nil
}

// SignOutWeChat ends a session. The binding stays, so signing in again needs only the password.
func (s *Service) SignOutWeChat(ctx context.Context, r WeChatRefresh) error {
	client, err := s.wechatClient(r.ClientID)
	if err != nil {
		return err
	}
	if err := s.allowIP(ctx, "wechat:ip", r.IP, s.limits.SignInIP); err != nil {
		return err
	}
	userID, _, _, _, err := s.wechatSession(ctx, client.ID, r.SessionID, r.Code)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "UPDATE auth.sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL", r.SessionID); err != nil {
			return fmt.Errorf("revoke session: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "session.revoke", Target: r.SessionID, Outcome: audit.Success,
		})
	})
}
