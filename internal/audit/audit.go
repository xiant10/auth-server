// Package audit writes the append-only audit log.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"t10-auth-server/internal/db"
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
}

// List returns one scope's newest rows.
func List(ctx context.Context, q db.Querier, scope string, limit int) ([]Record, error) {
	rows, err := q.Query(ctx,
		`SELECT at, actor, action, target, outcome FROM auth.audit_log
		 WHERE scope = $1 ORDER BY id DESC LIMIT $2`, scope, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit rows: %w", err)
	}
	records, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Record])
	if err != nil {
		return nil, fmt.Errorf("list audit rows: %w", err)
	}
	return records, nil
}

// Write appends one entry.
func Write(ctx context.Context, ex Execer, e Entry) error {
	detail := e.Detail
	if detail == nil {
		detail = map[string]any{}
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
