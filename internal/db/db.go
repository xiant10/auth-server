// Package db opens the Postgres pool and applies the embedded migrations, with
// t10-modkit's pgdb. What's this service's own is here: its schema and lock key.
package db

import (
	"context"
	"embed"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xiant10/t10-modkit/pgdb"
)

//go:embed migrations/*.sql
var migrations embed.FS

// migrationLock is the advisory lock key that serializes replicas at startup.
const migrationLock = 7410_0001

// Querier reads from the pool or from inside a transaction. Code holding a
// transaction must read through it: asking the pool for a second connection
// waits on itself, and a burst of such callers deadlocks the pool.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Open connects to Postgres and verifies the connection.
func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	return pgdb.Open(ctx, url, 0)
}

// Migrate applies every migration not yet recorded in auth.schema_migrations.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	return pgdb.Migrate(ctx, pool, pgdb.Migrations{FS: migrations, Schema: "auth", Lock: migrationLock})
}
