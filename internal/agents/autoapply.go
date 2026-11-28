package agents

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"auth-server/internal/audit"
)

// A person may let their assistant apply a module's propose actions without
// asking. The choice is theirs, per module (by action prefix) and per tenant.
// Grants keep the <prefix>:apply their runtime asked for, and Chain answers it
// only while the chain's person chose that module, so a change reaches live
// grants at once, and a tenant agent account's chain never carries it.

// ErrInvalidPrefix is a module value that isn't an action prefix.
var ErrInvalidPrefix = errors.New("a module is its lowercase action prefix, such as work")

var prefixPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// MaxAutoApply is how many modules one choice may name.
const MaxAutoApply = 50

const applySuffix = ":apply"

// AutoApply is the modules a person lets their assistant act in without
// asking, in one tenant, sorted.
func (s *Service) AutoApply(ctx context.Context, userID, tenantID string) ([]string, error) {
	return autoApply(ctx, s.pool, userID, tenantID)
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func autoApply(ctx context.Context, q querier, userID, tenantID string) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT prefix FROM auth.auto_apply WHERE user_id = $1 AND tenant_id = $2 ORDER BY prefix`, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read auto-apply: %w", err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("read auto-apply: %w", err)
	}
	return out, nil
}

// SetAutoApply replaces a person's choice in one tenant, and audits it, since
// it changes what their assistant may do.
func (s *Service) SetAutoApply(ctx context.Context, userID, tenantID string, modules []string) ([]string, error) {
	if tenantID == "" {
		return nil, ErrNoTenant
	}
	if len(modules) > MaxAutoApply {
		return nil, ErrInvalidPrefix
	}
	for _, m := range modules {
		if !prefixPattern.MatchString(m) {
			return nil, ErrInvalidPrefix
		}
	}
	want := slices.Clone(modules)
	slices.Sort(want)
	want = slices.Compact(want)
	var out []string
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		before, err := autoApply(ctx, tx, userID, tenantID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.auto_apply WHERE user_id = $1 AND tenant_id = $2 AND NOT (prefix = ANY($3))`, userID, tenantID, want); err != nil {
			return fmt.Errorf("set auto-apply: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.auto_apply (user_id, tenant_id, prefix) SELECT $1, $2, unnest($3::text[]) ON CONFLICT DO NOTHING`, userID, tenantID, want); err != nil {
			return fmt.Errorf("set auto-apply: %w", err)
		}
		out = want
		if slices.Equal(before, want) {
			return nil
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopeTenant(tenantID), Action: "auto_apply.set",
			Target: userID, Outcome: audit.Success, Detail: map[string]any{"before": before, "after": want},
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// narrowApply drops every <prefix>:apply the chain's person hasn't chosen from
// each link: all of them for a tenant agent account, which never signs in to
// choose. The grants themselves keep what was asked for.
func (s *Service) narrowApply(ctx context.Context, chain []Grant) ([]Grant, error) {
	if !slices.ContainsFunc(chain, func(g Grant) bool { return slices.ContainsFunc(g.Actions, isApply) }) {
		return chain, nil
	}
	leaf := chain[len(chain)-1]
	var chosen []string
	var person bool
	err := s.pool.QueryRow(ctx, `SELECT kind = 'person' FROM auth.users WHERE id = $1`, leaf.UserID).Scan(&person)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("read principal: %w", err)
	}
	if person {
		if chosen, err = s.AutoApply(ctx, leaf.UserID, leaf.TenantID); err != nil {
			return nil, err
		}
	}
	out := make([]Grant, len(chain))
	for i, g := range chain {
		g.Actions = slices.DeleteFunc(slices.Clone(g.Actions), func(a string) bool {
			return isApply(a) && !slices.Contains(chosen, strings.TrimSuffix(a, applySuffix))
		})
		out[i] = g
	}
	return out, nil
}

func isApply(action string) bool { return strings.HasSuffix(action, applySuffix) }
