// Package audit writes the append-only audit log.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"auth-server/internal/db"
)

// Outcomes recorded on an entry.
const (
	Success = "success"
	Denied  = "denied"
)

// ScopePlatform marks a platform-wide action.
const ScopePlatform = "platform"

// ScopeTenant returns the scope of an action inside one tenant.
func ScopeTenant(tenantID string) string { return "tenant:" + tenantID }

// ActorUser returns the actor value for a user.
func ActorUser(userID string) string { return "user:" + userID }

// Entry is one audit row.
type Entry struct {
	Actor   string
	Scope   string
	Action  string
	Target  string
	Outcome string
	Detail  map[string]any
}

// Execer is satisfied by both a pool and a transaction. Changes pass their
// transaction so the row commits with them. Denials pass the pool, because
// the transaction that was refused has rolled back.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Record is one stored audit row.
type Record struct {
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Target  string    `json:"target"`
	Outcome string    `json:"outcome"`
	// Name is the actor's sign-in name when the actor is a user, and IP the address the
	// request came from, when one was recorded.
	Name string `json:"name,omitempty"`
	IP   string `json:"ip,omitempty"`
}

// List returns one scope's newest rows.
func List(ctx context.Context, q db.Querier, scope string, limit int) ([]Record, error) {
	rows, err := q.Query(ctx,
		`SELECT a.at, a.actor, a.action, a.target, a.outcome,
		        COALESCE((SELECT i.value FROM auth.user_identifiers i WHERE i.user_id = substr(a.actor, 6)
		                  AND a.actor LIKE 'user:%' ORDER BY i.created_at LIMIT 1), ''),
		        COALESCE(a.detail->>'ip', '')
		 FROM auth.audit_log a WHERE a.scope = $1 ORDER BY a.id DESC LIMIT $2`, scope, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit rows: %w", err)
	}
	records, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Record])
	if err != nil {
		return nil, fmt.Errorf("list audit rows: %w", err)
	}
	return records, nil
}

type ipKey struct{}

// WithClientIP carries the address a request came from, so every row written while
// serving it records where the person was, including a refused sign-in.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, ipKey{}, ip)
}

// Write appends one entry. It adds the request's client address as "ip" when the
// context has one.
func Write(ctx context.Context, ex Execer, e Entry) error {
	detail := make(map[string]any, len(e.Detail)+1)
	for k, v := range e.Detail {
		detail[k] = v
	}
	if ip, _ := ctx.Value(ipKey{}).(string); ip != "" {
		detail["ip"] = ip
	}
	body, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("marshal audit detail: %w", err)
	}
	_, err = ex.Exec(ctx,
		`INSERT INTO auth.audit_log (actor, scope, action, target, outcome, detail)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		e.Actor, e.Scope, e.Action, e.Target, e.Outcome, body)
	if err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}
	return nil
}
