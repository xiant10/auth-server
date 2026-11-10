package identity

import (
	"context"
	"fmt"
	"slices"
	"time"
)

// SignIn is one browser this person is signed in on, with the web apps signed in
// through it. Native apps are devices, listed apart.
type SignIn struct {
	ID        string
	StartedAt time.Time
	// Apps are the names of the web apps open through this sign-in.
	Apps []string
}

// BrowserSignIns lists this person's live browser sign-ins, newest first.
func (s *Service) BrowserSignIns(ctx context.Context, userID string) ([]SignIn, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT b.id, b.created_at, COALESCE(array_agg(DISTINCT a.client_id) FILTER (WHERE a.id IS NOT NULL), '{}')
		FROM auth.sessions b
		LEFT JOIN auth.sessions a ON a.browser_session_id = b.id AND a.user_id = b.user_id AND a.revoked_at IS NULL
		     AND a.idle_expires_at > now() AND (a.absolute_expires_at IS NULL OR a.absolute_expires_at > now())
		WHERE b.user_id = $1 AND b.client_id = $2 AND b.revoked_at IS NULL
		  AND b.idle_expires_at > now() AND (b.absolute_expires_at IS NULL OR b.absolute_expires_at > now())
		GROUP BY b.id, b.created_at
		ORDER BY b.created_at DESC`, userID, browserClientID)
	if err != nil {
		return nil, fmt.Errorf("list browser sign-ins: %w", err)
	}
	defer rows.Close()
	var out []SignIn
	for rows.Next() {
		var in SignIn
		var clients []string
		if err := rows.Scan(&in.ID, &in.StartedAt, &clients); err != nil {
			return nil, fmt.Errorf("read browser sign-in: %w", err)
		}
		for _, id := range clients {
			name := id
			if client, ok := s.clients[id]; ok && client.Name != "" {
				name = client.Name
			}
			in.Apps = append(in.Apps, name)
		}
		slices.Sort(in.Apps)
		out = append(out, in)
	}
	return out, rows.Err()
}
