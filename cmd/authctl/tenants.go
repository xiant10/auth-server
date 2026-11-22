package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"auth-server/internal/directory"
)

// tenantAdd creates a tenant with no members, for an invitation to fill.
func tenantAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("tenant-add", flag.ExitOnError)
	tenantID := fs.String("tenant-id", "", "tenant ID such as ten_contoso")
	tenantName := fs.String("tenant-name", "", "tenant display name")
	ifMissing := fs.Bool("if-missing", false, "succeed without changes if the tenant exists")
	fs.Parse(args)
	if *tenantID == "" || *tenantName == "" {
		return errors.New("tenant-add needs --tenant-id and --tenant-name")
	}
	pool, err := open(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	return addTenant(ctx, pool, os.Stdout, *tenantID, *tenantName, *ifMissing)
}

func addTenant(ctx context.Context, pool *pgxpool.Pool, out io.Writer, id, name string, ifMissing bool) error {
	dir := directory.NewService(pool)
	if t, err := dir.GetTenant(ctx, id); err == nil {
		if !ifMissing {
			return fmt.Errorf("tenant %s exists", id)
		}
		fmt.Fprintf(out, "tenant %s exists (%s)\n", t.ID, t.Status)
		return nil
	} else if !errors.Is(err, directory.ErrNotFound) {
		return err
	}
	t, err := dir.Create(ctx, actor, id, name)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "tenant %s\n", t.ID)
	return nil
}

// invite prints a single-use link that registers a new account into a tenant
// (invite_url) or adds an existing one (join_url). It expires in 7 days.
func invite(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("invite", flag.ExitOnError)
	tenantID := fs.String("tenant-id", "", "tenant to join")
	role := fs.String("role", directory.RoleMember, "member or admin")
	publicURL := fs.String("public-url", os.Getenv("AUTH_PUBLIC_URL"), "auth-server's public URL; default AUTH_PUBLIC_URL")
	fs.Parse(args)
	if *tenantID == "" || *publicURL == "" {
		return errors.New("invite needs --tenant-id, and --public-url or AUTH_PUBLIC_URL")
	}
	pool, err := open(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	return inviteTo(ctx, pool, os.Stdout, *tenantID, *role, *publicURL)
}

func inviteTo(ctx context.Context, pool *pgxpool.Pool, out io.Writer, tenantID, role, publicURL string) error {
	if role != directory.RoleMember && role != directory.RoleAdmin {
		return fmt.Errorf("role must be %s or %s", directory.RoleMember, directory.RoleAdmin)
	}
	dir := directory.NewService(pool)
	t, err := dir.GetTenant(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("tenant %s: %w", tenantID, err)
	}
	if t.Status != directory.TenantActive {
		return fmt.Errorf("tenant %s is %s: an invitation to it can't be accepted", tenantID, t.Status)
	}
	token, err := dir.CreateInvitation(ctx, actor, tenantID, role)
	if err != nil {
		return err
	}
	base := strings.TrimRight(publicURL, "/")
	fmt.Fprintf(out, "invite_url %s/v1/register?invite=%s\njoin_url %s/v1/join?invite=%s\n", base, token, base, token)
	return nil
}

// tenantStatus suspends a tenant, so nobody signs in to it and its invitations
// stop working, or activates it again.
func tenantStatus(ctx context.Context, status string, args []string) error {
	fs := flag.NewFlagSet("tenant-"+status, flag.ExitOnError)
	tenantID := fs.String("tenant-id", "", "tenant")
	fs.Parse(args)
	if *tenantID == "" {
		return errors.New("needs --tenant-id")
	}
	pool, err := open(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := directory.NewService(pool).SetTenantStatus(ctx, actor, *tenantID, status); err != nil {
		return err
	}
	fmt.Printf("tenant %s %s\n", *tenantID, status)
	return nil
}
