// Command authctl runs operator tasks against the auth database.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/config"
	"t10-auth-server/internal/db"
	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/identity"
	"t10-auth-server/internal/roles"
	"t10-auth-server/internal/samples"
)

const usage = `usage: authctl <command> [flags]

commands:
  gen-key     print a new ES256 signing key as PEM
  bootstrap   create the first platform admin and their tenant
  add-user    create a user and add them to a tenant
  gen-totp-key  print a new AUTH_TOTP_KEY
  service-add      register a runtime or microservice and print its secret
  service-rotate   add a second secret and print it
  service-finish   retire the old secret after a rotation
  service-disable  stop a service, and every grant it holds
  service-enable   start it again
  permissions-purge  remove a retired module's permissions from every tenant's roles
  samples-add     create sample tenants and accounts (dev mode only)
  samples-remove  delete them and everything they gathered (dev mode only)

The password comes from AUTHCTL_PASSWORD, or else one line of stdin. service-add
takes a secret from AUTHCTL_SERVICE_SECRET, and generates one if that is unset.
`

const actor = "authctl"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "authctl:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("no command")
	}
	ctx := context.Background()
	switch args[0] {
	case "gen-key":
		return genKey()
	case "gen-totp-key":
		key := make([]byte, 32)
		rand.Read(key) // Never fails; see crypto/rand.
		fmt.Println(base64.StdEncoding.EncodeToString(key))
		return nil
	case "bootstrap":
		return bootstrap(ctx, args[1:])
	case "add-user":
		return addUser(ctx, args[1:])
	case "wechat-unbind":
		return wechatUnbind(ctx, args[1:])
	case "service-add":
		return serviceAdd(ctx, args[1:])
	case "service-rotate", "service-finish", "service-disable", "service-enable":
		return serviceChange(ctx, args[0], args[1:])
	case "permissions-purge":
		return permissionsPurge(ctx, args[1:])
	case "samples-add":
		return samplesAdd(ctx)
	case "samples-remove":
		return samplesRemove(ctx)
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func genKey() error {
	key, err := identity.GenerateSigningKey()
	if err != nil {
		return err
	}
	encoded, err := key.PEM()
	if err != nil {
		return err
	}
	fmt.Print(encoded)
	return nil
}

func bootstrap(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	username := fs.String("username", "", "sign-in name of the first platform admin")
	tenantID := fs.String("tenant-id", "", "tenant ID such as ten_acme; random if empty")
	tenantName := fs.String("tenant-name", "", "tenant display name")
	ifEmpty := fs.Bool("if-empty", false, "succeed without changes if a platform admin already exists")
	fs.Parse(args)
	if *username == "" || *tenantName == "" {
		return errors.New("bootstrap needs --username and --tenant-name")
	}

	pool, err := open(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	dir := directory.NewService(pool)

	exists, err := dir.HasPlatformAdmin(ctx)
	if err != nil {
		return err
	}
	if exists {
		if *ifEmpty {
			fmt.Println("already bootstrapped")
			return nil
		}
		return errors.New("a platform admin already exists")
	}

	password, err := readPassword()
	if err != nil {
		return err
	}
	ids, err := newIdentity(pool, dir)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		userID, err := ids.CreateUser(ctx, tx, actor, identity.NewUser{Name: *username, Password: password})
		if err != nil {
			return err
		}
		if err := dir.GrantPlatformAdmin(ctx, tx, actor, userID); err != nil {
			return err
		}
		tenant, err := dir.CreateTenant(ctx, tx, actor, *tenantID, *tenantName)
		if err != nil {
			return err
		}
		if _, err := dir.AddMember(ctx, tx, actor, tenant.ID, userID, directory.RoleAdmin); err != nil {
			return err
		}
		fmt.Printf("platform admin %s in tenant %s\n", userID, tenant.ID)
		return printRecoveryCodes(ctx, tx, ids, userID)
	})
}

func addUser(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("add-user", flag.ExitOnError)
	username := fs.String("username", "", "sign-in name")
	tenantID := fs.String("tenant-id", "", "tenant to join")
	role := fs.String("role", directory.RoleMember, "member or admin")
	fs.Parse(args)
	if *username == "" || *tenantID == "" {
		return errors.New("add-user needs --username and --tenant-id")
	}

	password, err := readPassword()
	if err != nil {
		return err
	}
	pool, err := open(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	dir := directory.NewService(pool)
	ids, err := newIdentity(pool, dir)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		userID, err := ids.CreateUser(ctx, tx, actor, identity.NewUser{Name: *username, Password: password})
		if err != nil {
			return err
		}
		if _, err := dir.AddMember(ctx, tx, actor, *tenantID, userID, *role); err != nil {
			return err
		}
		fmt.Printf("user %s in tenant %s\n", userID, *tenantID)
		return printRecoveryCodes(ctx, tx, ids, userID)
	})
}

// requireDevMode applies the server's own rule, so these commands run only
// where AUTH_DEV_MODE is on and the public URL is localhost.
func requireDevMode() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("sample accounts need a valid dev mode config: %w", err)
	}
	if !cfg.DevMode {
		return errors.New("sample accounts share a published password, so they need AUTH_DEV_MODE=true")
	}
	return nil
}

func samplesAdd(ctx context.Context) error {
	if err := requireDevMode(); err != nil {
		return err
	}
	pool, err := open(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	dir := directory.NewService(pool)
	ids, err := newIdentity(pool, dir)
	if err != nil {
		return err
	}
	if err := samples.Add(ctx, pool, ids, dir); err != nil {
		return err
	}
	fmt.Println("password for all:", samples.Password)
	for _, a := range samples.Accounts {
		fmt.Printf("  %-20s %s\n", a.Name, a.Tests)
	}
	fmt.Println("remove with: authctl samples-remove")
	return nil
}

func samplesRemove(ctx context.Context) error {
	if err := requireDevMode(); err != nil {
		return err
	}
	pool, err := open(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	removed, err := samples.Remove(ctx, pool)
	if err != nil {
		return err
	}
	fmt.Printf("removed %d users and %d tenants; their audit rows stay\n", removed.Users, removed.Tenants)
	return nil
}

// permissionsPurge removes a module's permissions for good. Taking a module out
// of an overlay only makes them unavailable; this is the deliberate second step.
// It reads AUTH_PERMISSIONS_DIR, as auth-server does, and refuses a module that
// is still deployed there.
func permissionsPurge(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("permissions-purge", flag.ExitOnError)
	module := fs.String("module", "", "the retired module's ID")
	confirm := fs.String("confirm", "", "the module's ID again, to confirm")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *module == "" || *confirm != *module {
		return errors.New("name the module with --module and repeat it with --confirm")
	}
	catalog, err := roles.LoadCatalog(os.Getenv("AUTH_PERMISSIONS_DIR"))
	if err != nil {
		return err
	}
	pool, err := open(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	removed, err := roles.NewService(pool, catalog).Purge(ctx, actor, *module)
	if errors.Is(err, roles.ErrDeployed) {
		return fmt.Errorf("%s is still in AUTH_PERMISSIONS_DIR: take it out of the overlay first", *module)
	}
	if err != nil {
		return err
	}
	fmt.Printf("removed %d role permissions of %s; roles and assignments stay\n", removed, *module)
	return nil
}

func printRecoveryCodes(ctx context.Context, tx pgx.Tx, ids *identity.Service, userID string) error {
	codes, err := ids.IssueRecoveryCodes(ctx, tx, userID)
	if err != nil {
		return err
	}
	fmt.Println("recovery codes, shown once:")
	for _, code := range codes {
		fmt.Println(" ", code)
	}
	return nil
}

func serviceAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("service-add", flag.ExitOnError)
	name := fs.String("name", "", "service name, as it appears in an audience")
	ifMissing := fs.Bool("if-missing", false, "do nothing if the service exists")
	fs.Parse(args)
	pool, err := open(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	ids, err := newIdentity(pool, directory.NewService(pool))
	if err != nil {
		return err
	}
	if *ifMissing {
		exists, err := ids.HasServiceAccount(ctx, *name)
		if err != nil || exists {
			return err
		}
	}
	supplied := os.Getenv("AUTHCTL_SERVICE_SECRET")
	secret, err := ids.AddServiceAccount(ctx, actor, *name, supplied)
	if err != nil {
		return err
	}
	if supplied == "" {
		fmt.Println("secret, shown once:", secret)
	}
	return nil
}

func serviceChange(ctx context.Context, command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	name := fs.String("name", "", "service name")
	fs.Parse(args)
	pool, err := open(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	ids, err := newIdentity(pool, directory.NewService(pool))
	if err != nil {
		return err
	}
	switch command {
	case "service-rotate":
		secret, err := ids.RotateServiceSecret(ctx, actor, *name)
		if err != nil {
			return err
		}
		fmt.Println("new secret, shown once:", secret)
		return nil
	case "service-finish":
		return ids.FinishServiceRotation(ctx, actor, *name)
	case "service-disable":
		return ids.SetServiceStatus(ctx, actor, *name, identity.ServiceDisabled)
	default:
		return ids.SetServiceStatus(ctx, actor, *name, identity.ServiceActive)
	}
}

func open(ctx context.Context) (*pgxpool.Pool, error) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return nil, errors.New("DATABASE_URL is required")
	}
	pool, err := db.Open(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// newIdentity builds the identity module for account creation, which signs no
// tokens and so needs no issuer.
func newIdentity(pool *pgxpool.Pool, dir *directory.Service) (*identity.Service, error) {
	hasher, err := identity.NewHasher(1)
	if err != nil {
		return nil, err
	}
	region := os.Getenv("AUTH_DEFAULT_REGION")
	if region == "" {
		region = "CN"
	}
	return identity.NewService(identity.Options{Pool: pool, Hasher: hasher, Tenants: dir, Region: region}), nil
}

func readPassword() (string, error) {
	if password := os.Getenv("AUTHCTL_PASSWORD"); password != "" {
		return password, nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("no password: set AUTHCTL_PASSWORD or pipe one line to stdin")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// wechatUnbind lets a person bind another WeChat, and ends their mini-program sessions.
func wechatUnbind(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("wechat-unbind", flag.ExitOnError)
	userID := fs.String("user-id", "", "the user whose binding to remove")
	fs.Parse(args)
	if *userID == "" {
		return errors.New("wechat-unbind needs --user-id")
	}
	pool, err := open(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE auth.wechat_bindings SET removed_at = now() WHERE user_id = $1 AND removed_at IS NULL", *userID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errors.New("that user has no WeChat binding")
		}
		_, err = tx.Exec(ctx, `UPDATE auth.sessions s SET revoked_at = now() WHERE s.user_id = $1 AND s.revoked_at IS NULL AND s.device_id IS NULL AND s.client_id = 't10-miniprogram'`, *userID)
		if err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{Actor: "system:authctl", Scope: audit.ScopePlatform, Action: "wechat.unbind", Target: *userID, Outcome: audit.Success})
	})
}
