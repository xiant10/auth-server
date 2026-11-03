// Command auth-server runs the t10 identity service.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"t10-auth-server/internal/agents"
	"t10-auth-server/internal/config"
	"t10-auth-server/internal/db"
	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/identity"
	"t10-auth-server/internal/server"
)

func main() {
	if err := run(); err != nil {
		slog.Error("auth-server stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	keys, err := loadKeys(cfg)
	if err != nil {
		return err
	}
	clients, err := identity.LoadClients(cfg.ClientsFile)
	if err != nil {
		return err
	}
	runtimes, err := agents.LoadRuntimes(cfg.ClientsFile)
	if err != nil {
		return err
	}
	totpKey := cfg.TOTPKey
	if totpKey == nil {
		// Config only allows this in dev mode.
		slog.Warn("AUTH_TOTP_KEY unset: using a throwaway dev key, TOTP enrollment dies with this process")
		totpKey = make([]byte, 32)
		rand.Read(totpKey) // Never fails; see crypto/rand.
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}

	// Half the CPUs for hashing, so a login flood cannot starve everything else.
	// GOMAXPROCS follows a container's CPU limit, and NumCPU would count the node.
	hasher, err := identity.NewHasher(max(1, runtime.GOMAXPROCS(0)/2))
	if err != nil {
		return err
	}
	issuer := identity.NewIssuer(cfg.PublicURL, keys)
	dir := directory.NewService(pool)
	ids := identity.NewService(identity.Options{
		Pool: pool, Hasher: hasher, Issuer: issuer, Tenants: dir, Clients: clients,
		Region: cfg.DefaultRegion, TOTPKey: totpKey, Limits: identity.DefaultLimits(),
	})
	for _, r := range runtimes {
		exists, err := ids.HasServiceAccount(ctx, r.Name)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("runtime %s has no service account: run authctl service-add --name %s", r.Name, r.Name)
		}
	}
	srv := server.New(server.Deps{
		Pool:      pool,
		Identity:  ids,
		Directory: dir,
		Agents: agents.NewService(pool, dir, issuer, agents.LiveKit{
			URL: cfg.LiveKitURL, APIKey: cfg.LiveKitAPIKey, APISecret: cfg.LiveKitAPISecret,
		}, runtimes),
		Issuer:       issuer,
		DevMode:      cfg.DevMode,
		PublicURL:    cfg.PublicURL,
		ConsoleURL:   cfg.ConsoleURL,
		WorkbenchURL: cfg.WorkbenchURL,
		TrustProxy:   cfg.TrustProxy,
	})
	go purgeLoop(ctx, ids)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errs := make(chan error, 1)
	go func() { errs <- httpServer.ListenAndServe() }()
	slog.Info("auth-server listening", "addr", cfg.ListenAddr, "issuer", cfg.PublicURL, "dev_mode", cfg.DevMode)

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

// purgeLoop clears expired rows. Every replica runs it, which is harmless.
func purgeLoop(ctx context.Context, ids *identity.Service) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ids.Purge(ctx); err != nil {
				slog.ErrorContext(ctx, "purge failed", "error", err)
			}
		}
	}
}

func loadKeys(cfg config.Config) (*identity.KeySet, error) {
	var current, next *identity.SigningKey
	var err error
	if cfg.SigningKeyCurrent != "" {
		current, err = identity.ParseSigningKey(cfg.SigningKeyCurrent)
	} else {
		// Config only allows this in dev mode.
		slog.Warn("AUTH_SIGNING_KEY_CURRENT unset: using a throwaway dev key, tokens die with this process")
		current, err = identity.GenerateSigningKey()
	}
	if err != nil {
		return nil, fmt.Errorf("current signing key: %w", err)
	}
	if cfg.SigningKeyNext != "" {
		if next, err = identity.ParseSigningKey(cfg.SigningKeyNext); err != nil {
			return nil, fmt.Errorf("next signing key: %w", err)
		}
	}
	return identity.NewKeySet(current, next), nil
}
