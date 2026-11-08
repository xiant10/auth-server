package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"

	"t10-auth-server/internal/audit"
)

const browserLogoutAudience = "t10:browser-logout"

// MintBrowserLogout authorizes only ending the browser sign-in behind this
// session. It is deliberately not an access token and cannot authorize API requests.
func (i *Issuer) MintBrowserLogout(userID, sessionID, redirect string) (string, error) {
	token, _, err := i.sign(userID, []string{browserLogoutAudience}, time.Minute, Claims{SessionID: sessionID, LogoutRedirect: redirect})
	return token, err
}

func (i *Issuer) VerifyBrowserLogout(raw string) (*Claims, error) {
	return i.verify(raw, jwt.WithAudience(browserLogoutAudience))
}

// EndBrowser ends a browser sign-in and every web app's session started from it,
// given any one of those sessions. Native apps have their own sign-in, so they stay.
func (s *Service) EndBrowser(ctx context.Context, userID, sessionID string) error {
	web := make([]string, 0, len(s.clients))
	for id, client := range s.clients {
		if client.Type == ClientConfidential {
			web = append(web, id)
		}
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var root string
		err := tx.QueryRow(ctx,
			"SELECT COALESCE(browser_session_id, id) FROM auth.sessions WHERE id = $1 AND user_id = $2",
			sessionID, userID).Scan(&root)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("find browser session: %w", err)
		}
		_, err = tx.Exec(ctx,
			`UPDATE auth.sessions SET revoked_at = now()
			 WHERE user_id = $1 AND revoked_at IS NULL
			   AND (id = $2 OR id = $3 OR (browser_session_id = $2 AND client_id = ANY($4)))`,
			userID, root, sessionID, web)
		if err != nil {
			return fmt.Errorf("revoke browser sessions: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "session.revoke",
			Target: root, Outcome: audit.Success, Detail: map[string]any{"browser": true},
		})
	})
}
