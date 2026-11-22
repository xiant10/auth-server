package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"regexp"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"auth-server/internal/db"
	"auth-server/internal/directory"
)

// testPool rebuilds the auth schema on TEST_DATABASE_URL, as the server's tests
// do, so never point it at a real database.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL not set")
		}
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, "DROP SCHEMA IF EXISTS auth CASCADE"); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

// A prospect's tenant: created once, invited into as admin, suspended at the
// end of the trial, after which no invitation to it is made.
func TestProspectTenant(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	var out bytes.Buffer

	if err := addTenant(ctx, pool, &out, "ten_contoso", "Contoso", false); err != nil {
		t.Fatal(err)
	}
	if err := addTenant(ctx, pool, &out, "ten_contoso", "Contoso", false); err == nil {
		t.Fatal("a second tenant-add without --if-missing succeeded")
	}
	if err := addTenant(ctx, pool, &out, "ten_contoso", "Contoso", true); err != nil {
		t.Fatalf("--if-missing: %v", err)
	}

	out.Reset()
	if err := inviteTo(ctx, pool, &out, "ten_contoso", directory.RoleAdmin, "https://t10-auth.example/"); err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`^invite_url https://t10-auth\.example/v1/register\?invite=(\S+)\njoin_url https://t10-auth\.example/v1/join\?invite=(\S+)\n$`).FindStringSubmatch(out.String())
	if m == nil || m[1] != m[2] {
		t.Fatalf("printed %q", out.String())
	}
	sum := sha256.Sum256([]byte(m[1]))
	var tenant, role string
	if err := pool.QueryRow(ctx, "SELECT tenant_id, role FROM auth.invitations WHERE token_hash = $1", sum[:]).Scan(&tenant, &role); err != nil {
		t.Fatalf("the printed link has no invitation: %v", err)
	}
	if tenant != "ten_contoso" || role != directory.RoleAdmin {
		t.Fatalf("invitation to %s as %s", tenant, role)
	}

	if err := inviteTo(ctx, pool, &out, "ten_contoso", "owner", "https://x"); err == nil {
		t.Error("an unknown role was accepted")
	}
	if err := inviteTo(ctx, pool, &out, "ten_missing", directory.RoleAdmin, "https://x"); err == nil {
		t.Error("an invitation to a missing tenant was made")
	}

	dir := directory.NewService(pool)
	if err := dir.SetTenantStatus(ctx, actor, "ten_contoso", directory.TenantSuspended); err != nil {
		t.Fatal(err)
	}
	if err := inviteTo(ctx, pool, &out, "ten_contoso", directory.RoleAdmin, "https://x"); err == nil {
		t.Error("an invitation to a suspended tenant was made")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := dir.AcceptInvitation(ctx, tx, actor, m[1], "usr_x"); err == nil {
		t.Error("an invitation to a suspended tenant was accepted")
	}
}
