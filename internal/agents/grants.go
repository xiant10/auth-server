package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/ids"
)

const (
	// DefaultGrantTTL is how long a grant lasts, and what each new user request
	// extends it to.
	DefaultGrantTTL = 8 * time.Hour
	// MaxGrantLife caps a grant from its creation, however often it is extended.
	MaxGrantLife = 24 * time.Hour
	// MaxGrantDepth is the longest chain, counting the root.
	MaxGrantDepth = 4
	// DelegatedTokenTTL is the lifetime of a token minted from a grant.
	DelegatedTokenTTL = 5 * time.Minute
	// StandingGrantTTL is how long a person's consent to future runs lasts, and
	// what using t10 renews it to.
	StandingGrantTTL = 90 * 24 * time.Hour
	// standingRenewal is how stale a standing grant's expiry gets before a
	// refresh renews it, so a busy person doesn't write on every refresh.
	standingRenewal = 24 * time.Hour
	// StandingRuntime is the only runtime that may hold a standing grant.
	StandingRuntime = "t10-automations"
)

// Triggers say why a run is running. A person started user and voice runs; the
// others run unattended, from a standing grant, and name their automation.
const (
	TriggerUser     = "user"
	TriggerVoice    = "voice"
	TriggerSchedule = "schedule"
	TriggerEvent    = "event"
	TriggerWebhook  = "webhook"
)

// unattended are the triggers a standing grant's children may carry.
var unattended = []string{TriggerSchedule, TriggerEvent, TriggerWebhook}

var automationPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Errors returned by the grant calls.
var (
	// ErrGrantInvalid covers a grant that is unknown, revoked or not the
	// caller's, so a caller can't tell them apart.
	ErrGrantInvalid = errors.New("grant is invalid")
	// ErrGrantExpired means a live user token could still renew it.
	ErrGrantExpired = errors.New("grant has expired")
	// ErrGrantRequest means the request itself asks for too much.
	ErrGrantRequest = errors.New("grant request not allowed")
)

// Caller is an authenticated service account.
type Caller struct {
	ID   string
	Name string
}

// Grant is one agent execution.
type Grant struct {
	ID          string          `json:"id"`
	ParentID    string          `json:"parent_id,omitempty"`
	RuntimeID   string          `json:"runtime_id"`
	UserID      string          `json:"user_id"`
	TenantID    string          `json:"tenant_id"`
	Actions     []string        `json:"actions"`
	Audiences   []string        `json:"audiences"`
	Constraints json.RawMessage `json:"constraints"`
	Depth       int             `json:"depth"`
	// Trigger is why its run is running. A standing grant has none.
	Trigger    string     `json:"trigger,omitempty"`
	Automation string     `json:"automation,omitempty"`
	Standing   bool       `json:"standing,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"-"`
}

// GrantRequest is what a runtime asks for. Model output never supplies it.
type GrantRequest struct {
	Actions     []string
	Audiences   []string
	Constraints json.RawMessage
	TTL         time.Duration
	// Standing asks for a root that consents to future runs, for
	// t10-automations only.
	Standing bool
	// Trigger and Automation are set only on a standing grant's child, which is
	// one firing. Every other child inherits its parent's.
	Trigger    string
	Automation string
}

func (r GrantRequest) ttl() time.Duration {
	if r.TTL > 0 {
		return min(r.TTL, MaxGrantLife)
	}
	return DefaultGrantTTL
}

func (r GrantRequest) constraints() (json.RawMessage, error) {
	if len(r.Constraints) == 0 {
		return json.RawMessage("{}"), nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(r.Constraints, &object); err != nil || object == nil {
		return nil, fmt.Errorf("%w: constraints must be a JSON object", ErrGrantRequest)
	}
	return r.Constraints, nil
}

// checkRuntime applies the reviewed list, which binds roots and children alike.
func (s *Service) checkRuntime(caller Caller, r GrantRequest) error {
	runtime, ok := s.runtime(caller.Name)
	if !ok {
		return fmt.Errorf("%w: %s is not a runtime", ErrGrantRequest, caller.Name)
	}
	if len(r.Actions) == 0 || len(r.Audiences) == 0 {
		return fmt.Errorf("%w: actions and audiences are required", ErrGrantRequest)
	}
	if !subset(r.Actions, runtime.Actions) || !subset(r.Audiences, runtime.Audiences) {
		return fmt.Errorf("%w: beyond what this runtime may request", ErrGrantRequest)
	}
	return nil
}

// CreateRoot starts a chain for a user whose live token the handler verified.
// A standing root is that person's consent to runs that start later.
func (s *Service) CreateRoot(ctx context.Context, caller Caller, userID, tenantID string, r GrantRequest) (*Grant, error) {
	if tenantID == "" {
		return nil, ErrNoTenant
	}
	if err := s.checkRuntime(caller, r); err != nil {
		return nil, err
	}
	if r.Trigger != "" || r.Automation != "" {
		return nil, fmt.Errorf("%w: only a standing grant's child names a trigger", ErrGrantRequest)
	}
	if r.Standing && caller.Name != StandingRuntime {
		return nil, fmt.Errorf("%w: only %s may hold a standing grant", ErrGrantRequest, StandingRuntime)
	}
	constraints, err := r.constraints()
	if err != nil {
		return nil, err
	}
	if err := s.membership.CheckActive(ctx, userID, tenantID); err != nil {
		return nil, err
	}
	g := &Grant{
		ID: ids.New("grt"), RuntimeID: caller.ID, UserID: userID, TenantID: tenantID,
		Actions: r.Actions, Audiences: r.Audiences, Constraints: constraints, Depth: 1, Trigger: TriggerUser,
	}
	ttl := r.ttl()
	if r.Standing {
		g.Standing, g.Trigger, ttl = true, "", StandingGrantTTL
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error { return insertGrant(ctx, tx, g, ttl) })
	if err != nil {
		return nil, err
	}
	return g, nil
}

// CreateChild narrows a live grant: fewer or equal actions and audiences, an
// expiry no later than the parent's, and the same user and tenant.
func (s *Service) CreateChild(ctx context.Context, caller Caller, parentID string, r GrantRequest) (*Grant, error) {
	if err := s.checkRuntime(caller, r); err != nil {
		return nil, err
	}
	constraints, err := r.constraints()
	if err != nil {
		return nil, err
	}
	chain, err := s.liveChain(ctx, caller, parentID)
	if err != nil {
		return nil, err
	}
	parent := chain[len(chain)-1]
	if parent.Depth >= MaxGrantDepth {
		return nil, fmt.Errorf("%w: chain is at its depth limit", ErrGrantRequest)
	}
	if !subset(r.Actions, parent.Actions) || !subset(r.Audiences, parent.Audiences) {
		return nil, fmt.Errorf("%w: a child can only narrow its parent", ErrGrantRequest)
	}
	if r.Standing {
		return nil, fmt.Errorf("%w: a standing grant is always a root", ErrGrantRequest)
	}
	trigger, automation, err := childTrigger(parent, r)
	if err != nil {
		return nil, err
	}
	g := &Grant{
		ID: ids.New("grt"), ParentID: parent.ID, RuntimeID: caller.ID, UserID: parent.UserID, TenantID: parent.TenantID,
		Actions: r.Actions, Audiences: r.Audiences, Constraints: constraints, Depth: parent.Depth + 1,
		Trigger: trigger, Automation: automation,
	}
	ttl := min(r.ttl(), time.Until(parent.ExpiresAt))
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error { return insertGrant(ctx, tx, g, ttl) })
	if err != nil {
		return nil, err
	}
	return g, nil
}

// CreateFiring makes one firing of an automation: a child of a standing grant,
// which mints no token of its own, so the runtime names it by ID. Only the
// runtime that holds the consent may, and the chain is checked as for any mint,
// so a suspended person or a revoked consent stops the next firing.
func (s *Service) CreateFiring(ctx context.Context, caller Caller, standingID string, r GrantRequest) (*Grant, error) {
	chain, err := s.chain(ctx, standingID)
	if err != nil {
		return nil, err
	}
	if len(chain) != 1 || !chain[0].Standing || chain[0].RuntimeID != caller.ID {
		return nil, ErrGrantInvalid
	}
	return s.CreateChild(ctx, caller, standingID, r)
}

// childTrigger decides a child's trigger. A standing grant's child is one
// firing, so it must say which kind and which automation. Any other child keeps
// its parent's, so a run can't shed an unattended trigger by delegating.
func childTrigger(parent Grant, r GrantRequest) (string, string, error) {
	if !parent.Standing {
		if r.Trigger != "" || r.Automation != "" {
			return "", "", fmt.Errorf("%w: a child keeps its parent's trigger", ErrGrantRequest)
		}
		return parent.Trigger, parent.Automation, nil
	}
	if !slices.Contains(unattended, r.Trigger) {
		return "", "", fmt.Errorf("%w: a standing grant's child needs a trigger of schedule, event or webhook", ErrGrantRequest)
	}
	if !automationPattern.MatchString(r.Automation) {
		return "", "", fmt.Errorf("%w: a standing grant's child needs its automation's ID", ErrGrantRequest)
	}
	return r.Trigger, r.Automation, nil
}

func insertGrant(ctx context.Context, tx pgx.Tx, g *Grant, ttl time.Duration) error {
	var parent *string
	if g.ParentID != "" {
		parent = &g.ParentID
	}
	err := tx.QueryRow(ctx,
		`INSERT INTO auth.agent_grants (id, parent_id, runtime_id, user_id, tenant_id, actions, audiences, constraints, depth,
		                                trigger, automation, standing, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now() + make_interval(secs => $13))
		 RETURNING created_at, expires_at`,
		g.ID, parent, g.RuntimeID, g.UserID, g.TenantID, g.Actions, g.Audiences, string(g.Constraints), g.Depth,
		g.Trigger, g.Automation, g.Standing, ttl.Seconds(),
	).Scan(&g.CreatedAt, &g.ExpiresAt)
	if err != nil {
		return fmt.Errorf("insert grant: %w", err)
	}
	return audit.Write(ctx, tx, audit.Entry{
		Actor: "service:" + g.RuntimeID, Scope: audit.ScopeTenant(g.TenantID), Action: "grant.create", Target: g.ID,
		Outcome: audit.Success, Detail: map[string]any{
			"user": g.UserID, "parent": g.ParentID, "actions": g.Actions, "audiences": g.Audiences,
			"trigger": g.Trigger, "automation": g.Automation, "standing": g.Standing,
		},
	})
}

// mayUse is the runtime that holds a grant, or a service listed on it.
func mayUse(g Grant, caller Caller) bool {
	return g.RuntimeID == caller.ID || slices.Contains(g.Audiences, caller.Name)
}

// chain returns a grant and its ancestors, root first.
func (s *Service) chain(ctx context.Context, id string) ([]Grant, error) {
	rows, err := s.pool.Query(ctx,
		`WITH RECURSIVE chain AS (
			SELECT g.*, 0 AS distance FROM auth.agent_grants g WHERE g.id = $1
			UNION ALL
			SELECT g.*, c.distance + 1 FROM auth.agent_grants g JOIN chain c ON g.id = c.parent_id
		)
		SELECT c.id, COALESCE(c.parent_id, ''), c.runtime_id, c.user_id, c.tenant_id, c.actions, c.audiences,
		       c.constraints, c.depth, c.trigger, c.automation, c.standing, c.created_at, c.expires_at,
		       CASE WHEN sa.status = 'active' THEN c.revoked_at ELSE COALESCE(c.revoked_at, now()) END
		FROM chain c JOIN auth.service_accounts sa ON sa.id = c.runtime_id
		ORDER BY c.distance DESC`, id)
	if err != nil {
		return nil, fmt.Errorf("read grant chain: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Grant, error) {
		var g Grant
		err := row.Scan(&g.ID, &g.ParentID, &g.RuntimeID, &g.UserID, &g.TenantID, &g.Actions, &g.Audiences,
			&g.Constraints, &g.Depth, &g.Trigger, &g.Automation, &g.Standing, &g.CreatedAt, &g.ExpiresAt, &g.RevokedAt)
		return g, err
	})
}

// liveChain returns the chain only if the caller may use its leaf and nothing
// along it has ended: every ancestor, its runtime, the user and the membership
// are checked each time, so one revocation reaches all descendants.
func (s *Service) liveChain(ctx context.Context, caller Caller, id string) ([]Grant, error) {
	chain, err := s.chain(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, ErrGrantInvalid
	}
	leaf := chain[len(chain)-1]
	if !mayUse(leaf, caller) {
		s.denyGrant(ctx, caller, leaf, "not_listed")
		return nil, ErrGrantInvalid
	}
	now := time.Now()
	expired := false
	for _, g := range chain {
		if g.RevokedAt != nil {
			s.denyGrant(ctx, caller, leaf, "revoked")
			return nil, ErrGrantInvalid
		}
		expired = expired || !g.ExpiresAt.After(now)
	}
	if err := s.membership.CheckActive(ctx, leaf.UserID, leaf.TenantID); err != nil {
		s.denyGrant(ctx, caller, leaf, "membership")
		return nil, ErrGrantInvalid
	}
	if expired {
		return nil, ErrGrantExpired
	}
	return chain, nil
}

// Exchange mints a delegated token for a grant. Tokens come only from here, so
// a stopped grant stops within one token's lifetime.
func (s *Service) Exchange(ctx context.Context, caller Caller, grantID string) (string, time.Time, *Grant, error) {
	chain, err := s.liveChain(ctx, caller, grantID)
	if err != nil {
		return "", time.Time{}, nil, err
	}
	g := chain[len(chain)-1]
	// Consent to future runs isn't a run: each firing is a child, and mints.
	if g.Standing {
		s.denyGrant(ctx, caller, g, "standing")
		return "", time.Time{}, nil, ErrGrantInvalid
	}
	ttl := min(DelegatedTokenTTL, time.Until(g.ExpiresAt))
	token, expires, err := s.signer.MintDelegated(s.delegation(g, s.tokenAudiences(g)), ttl)
	if err != nil {
		return "", time.Time{}, nil, err
	}
	return token, expires, &g, nil
}

// tokenAudiences is who a grant's tokens are for: its runtime's tool gateway
// alone when the runtime sets one, so a harness can reach a module only through
// it, and otherwise the grant's audiences.
func (s *Service) tokenAudiences(g Grant) []string {
	// A grant made before its runtime listed the gateway can't be checked
	// there, so its tokens keep the grant's audiences until it ends.
	if runtime, ok := s.runtimeByID(g.RuntimeID); ok && runtime.ToolAudience != "" && s.toolGateway && slices.Contains(g.Audiences, runtime.ToolAudience) {
		return []string{runtime.ToolAudience}
	}
	return g.Audiences
}

func (s *Service) delegation(g Grant, audiences []string) Delegation {
	return Delegation{
		UserID: g.UserID, TenantID: g.TenantID, RuntimeID: g.RuntimeID, GrantID: g.ID, Scope: scopeOf(g.Actions),
		Audiences: audiences, Trigger: g.Trigger, Automation: g.Automation,
	}
}

// TokenExchange trades a delegated token presented to the caller for one with
// a single other audience on the same grant, for the tool gateway to forward a
// call to that module. The caller must be allowed to exchange and named in the
// token's audience, the target must be on the grant, and the whole chain is
// checked as for any mint. The new token says the same thing about who and
// why, and ends no later than the one it replaces.
func (s *Service) TokenExchange(ctx context.Context, caller Caller, grantID string, subjectAudiences []string, subjectExpires time.Time, audience string) (string, time.Time, error) {
	if !slices.Contains(s.exchangers, caller.Name) {
		return "", time.Time{}, fmt.Errorf("%w: %s may not exchange tokens", ErrGrantRequest, caller.Name)
	}
	if !slices.Contains(subjectAudiences, caller.Name) {
		return "", time.Time{}, fmt.Errorf("%w: the token wasn't presented to %s", ErrGrantRequest, caller.Name)
	}
	if audience == "" || audience == audienceT10 || audience == caller.Name {
		return "", time.Time{}, fmt.Errorf("%w: audience %q can't be asked for", ErrGrantRequest, audience)
	}
	chain, err := s.liveChain(ctx, caller, grantID)
	if err != nil {
		return "", time.Time{}, err
	}
	g := chain[len(chain)-1]
	if !slices.Contains(g.Audiences, audience) {
		s.denyGrant(ctx, caller, g, "audience_not_on_grant")
		return "", time.Time{}, fmt.Errorf("%w: %s isn't on the grant", ErrGrantRequest, audience)
	}
	ttl := min(DelegatedTokenTTL, time.Until(g.ExpiresAt), time.Until(subjectExpires))
	if ttl <= 0 {
		return "", time.Time{}, ErrGrantExpired
	}
	return s.signer.MintDelegated(s.delegation(g, []string{audience}), ttl)
}

// Chain returns a live grant's ancestors for a target service to enforce.
func (s *Service) Chain(ctx context.Context, caller Caller, grantID string) ([]Grant, error) {
	return s.liveChain(ctx, caller, grantID)
}

// Extend renews a grant for a new user request: the handler proved a live token
// for this user and tenant. A revoked grant stays revoked, and an extension
// never passes the 24-hour cap or the parent's expiry.
func (s *Service) Extend(ctx context.Context, caller Caller, grantID, userID, tenantID string) (*Grant, error) {
	chain, err := s.chain(ctx, grantID)
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, ErrGrantInvalid
	}
	g := chain[len(chain)-1]
	if !mayUse(g, caller) || g.UserID != userID || g.TenantID != tenantID {
		s.denyGrant(ctx, caller, g, "not_listed")
		return nil, ErrGrantInvalid
	}
	if slices.ContainsFunc(chain, func(a Grant) bool { return a.RevokedAt != nil }) {
		return nil, ErrGrantInvalid
	}
	if err := s.membership.CheckActive(ctx, userID, tenantID); err != nil {
		return nil, ErrGrantInvalid
	}
	limit, extension := g.CreatedAt.Add(MaxGrantLife), DefaultGrantTTL
	if len(chain) > 1 {
		limit = chain[len(chain)-2].ExpiresAt
	}
	// A person's consent has no cap from creation: using t10 keeps it.
	if g.Standing {
		limit, extension = time.Now().Add(StandingGrantTTL), StandingGrantTTL
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`UPDATE auth.agent_grants
			 SET expires_at = GREATEST(expires_at, LEAST(now() + make_interval(secs => $2), $3))
			 WHERE id = $1 RETURNING expires_at`,
			g.ID, extension.Seconds(), limit).Scan(&g.ExpiresAt)
		if err != nil {
			return fmt.Errorf("extend grant: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopeTenant(tenantID), Action: "grant.extend",
			Target: g.ID, Outcome: audit.Success,
		})
	})
	if err != nil {
		return nil, err
	}
	if !g.ExpiresAt.After(time.Now()) {
		return nil, ErrGrantExpired
	}
	return &g, nil
}

// Revoke stops a grant, and through the chain check all its descendants.
func (s *Service) Revoke(ctx context.Context, caller Caller, grantID string) error {
	chain, err := s.chain(ctx, grantID)
	if err != nil {
		return err
	}
	if len(chain) == 0 || !mayUse(chain[len(chain)-1], caller) {
		return ErrGrantInvalid
	}
	g := chain[len(chain)-1]
	return s.revoke(ctx, "service:"+caller.ID, g.ID, g.TenantID)
}

func (s *Service) revoke(ctx context.Context, actor, grantID, tenantID string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			"UPDATE auth.agent_grants SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL", grantID)
		if err != nil {
			return fmt.Errorf("revoke grant: %w", err)
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: actor, Scope: audit.ScopeTenant(tenantID), Action: "grant.revoke", Target: grantID, Outcome: audit.Success,
		})
	})
}

// GrantRow is a grant as an admin sees it.
type GrantRow struct {
	Grant
	// Who is the user's first sign-in name.
	Who string
	// Stopped means this grant or an ancestor was revoked.
	Stopped bool
}

// Running reports whether the grant can still mint tokens, as far as its own
// chain goes. A user or tenant check may stop it as well.
func (g GrantRow) Running() bool { return !g.Stopped && g.ExpiresAt.After(time.Now()) }

// ListTenantGrants returns a tenant's most recent grants, running ones first.
func (s *Service) ListTenantGrants(ctx context.Context, tenantID string, limit int) ([]GrantRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT g.id, COALESCE(g.parent_id, ''), g.runtime_id, g.user_id, g.tenant_id, g.actions, g.audiences,
		        g.depth, g.trigger, g.automation, g.standing, g.created_at, g.expires_at,
		        COALESCE((SELECT i.value FROM auth.user_identifiers i
		                  WHERE i.user_id = g.user_id ORDER BY i.created_at, i.value LIMIT 1), ''),
		        s.stopped
		 FROM auth.agent_grants g
		 CROSS JOIN LATERAL (
			WITH RECURSIVE up AS (
				SELECT id, parent_id, revoked_at FROM auth.agent_grants WHERE id = g.id
				UNION ALL
				SELECT a.id, a.parent_id, a.revoked_at FROM auth.agent_grants a JOIN up ON a.id = up.parent_id
			)
			SELECT bool_or(revoked_at IS NOT NULL) AS stopped FROM up
		 ) s
		 WHERE g.tenant_id = $1
		 ORDER BY (NOT s.stopped AND g.expires_at > now()) DESC, g.created_at DESC, g.id LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	grants, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (GrantRow, error) {
		var g GrantRow
		err := row.Scan(&g.ID, &g.ParentID, &g.RuntimeID, &g.UserID, &g.TenantID, &g.Actions, &g.Audiences,
			&g.Depth, &g.Trigger, &g.Automation, &g.Standing, &g.CreatedAt, &g.ExpiresAt, &g.Who, &g.Stopped)
		return g, err
	})
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	return grants, nil
}

// RevokeInTenant stops a grant for a tenant's admin. The tenant comes from the
// page they hold rights over, so another tenant's grant simply isn't found.
func (s *Service) RevokeInTenant(ctx context.Context, actor, tenantID, grantID string) error {
	var found bool
	err := s.pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM auth.agent_grants WHERE id = $1 AND tenant_id = $2)", grantID, tenantID).Scan(&found)
	if err != nil {
		return fmt.Errorf("read grant: %w", err)
	}
	if !found {
		return ErrGrantInvalid
	}
	return s.revoke(ctx, actor, grantID, tenantID)
}

// RenewStanding keeps a person's standing grants alive while they use t10, in
// the caller's transaction. It writes only when an expiry is a day stale, so a
// refresh every few minutes costs one read. Expired or revoked grants stay
// ended: consent that lapsed needs a live token to give again.
func RenewStanding(ctx context.Context, tx pgx.Tx, userID string) error {
	_, err := tx.Exec(ctx,
		`UPDATE auth.agent_grants SET expires_at = now() + make_interval(secs => $2)
		 WHERE user_id = $1 AND standing AND revoked_at IS NULL AND expires_at > now()
		   AND expires_at < now() + make_interval(secs => $3)`,
		userID, StandingGrantTTL.Seconds(), (StandingGrantTTL - standingRenewal).Seconds())
	if err != nil {
		return fmt.Errorf("renew standing grants: %w", err)
	}
	return nil
}

// RevokeUserGrants stops everything running for a user, in the caller's
// transaction, so it commits with the sign-out or reset that caused it.
func RevokeUserGrants(ctx context.Context, tx pgx.Tx, userID string) error {
	_, err := tx.Exec(ctx,
		"UPDATE auth.agent_grants SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL", userID)
	if err != nil {
		return fmt.Errorf("revoke user grants: %w", err)
	}
	return nil
}

// RevokeMemberGrants stops a user's grants in one tenant. A grant must not come
// back to life if the membership is restored later.
func RevokeMemberGrants(ctx context.Context, tx pgx.Tx, userID, tenantID string) error {
	_, err := tx.Exec(ctx,
		"UPDATE auth.agent_grants SET revoked_at = now() WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL",
		userID, tenantID)
	if err != nil {
		return fmt.Errorf("revoke member grants: %w", err)
	}
	return nil
}

func (s *Service) denyGrant(ctx context.Context, caller Caller, g Grant, reason string) {
	err := audit.Write(context.WithoutCancel(ctx), s.pool, audit.Entry{
		Actor: "service:" + caller.ID, Scope: audit.ScopeTenant(g.TenantID), Action: "grant.exchange", Target: g.ID,
		Outcome: audit.Denied, Detail: map[string]any{"reason": reason},
	})
	if err != nil {
		slog.ErrorContext(ctx, "audit write failed", "error", err)
	}
}
