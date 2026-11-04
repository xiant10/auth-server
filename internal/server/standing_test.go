package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"t10-auth-server/internal/agents"
	"t10-auth-server/internal/directory"
)

// standing makes ada's consent to future runs, as t10-automations does while
// she's signed in.
func (h *harness) standing(userToken string) string {
	h.t.Helper()
	status, body := h.createGrant(firingRuntime, map[string]any{
		"subject_token": userToken, "standing": true, "actions": []string{"crm:read"}, "audiences": []string{piRuntime, listedService},
	})
	h.wantStatus(status, body, http.StatusCreated)
	if body["standing"] != true || body["trigger"] != nil {
		h.t.Fatalf("standing grant: %v", body)
	}
	expires, _ := time.Parse(time.RFC3339Nano, body["expires_at"].(string))
	if time.Until(expires) < agents.StandingGrantTTL-time.Hour {
		h.t.Fatalf("a standing grant lasts %v", time.Until(expires))
	}
	return body["id"].(string)
}

// firing is one run of an automation: a child of the standing grant.
func (h *harness) firing(standing string, req map[string]any) (int, map[string]any) {
	h.t.Helper()
	// A standing grant mints nothing, so t10-automations names it by ID.
	req["parent_id"] = standing
	return h.createGrant(firingRuntime, req)
}

func TestStandingGrantFiresScheduledRuns(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	userID := h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	user := h.login("ada", "ten_acme")
	standing := h.standing(user)

	// Consent isn't a run, so it never mints a token, and only its holder fires it.
	h.wantStopped(firingRuntime, standing)
	if status, body := h.createGrant(piRuntime, map[string]any{
		"parent_id": standing, "trigger": "schedule", "automation": "au_1", "actions": []string{"crm:read"}, "audiences": []string{piRuntime},
	}); status != http.StatusBadRequest {
		t.Errorf("another runtime fired it: %d %v", status, body)
	}

	for name, req := range map[string]map[string]any{
		"no trigger":         {},
		"a person's trigger": {"trigger": "user", "automation": "au_1"},
		"no automation":      {"trigger": "schedule"},
		"a bad automation":   {"trigger": "schedule", "automation": "au 1"},
	} {
		req["actions"], req["audiences"] = []string{"crm:read"}, []string{piRuntime}
		if status, body := h.firing(standing, req); status != http.StatusBadRequest {
			t.Errorf("%s: %d %v", name, status, body)
		}
	}
	status, body := h.firing(standing, map[string]any{
		"trigger": "schedule", "automation": "au_brief", "actions": []string{"crm:read"}, "audiences": []string{piRuntime, listedService},
	})
	h.wantStatus(status, body, http.StatusCreated)
	run := body["id"].(string)
	expires, _ := time.Parse(time.RFC3339Nano, body["expires_at"].(string))
	if left := time.Until(expires); left > agents.DefaultGrantTTL || left < agents.DefaultGrantTTL-time.Minute {
		t.Errorf("a firing lasts %v", left)
	}

	token := h.mint(firingRuntime, run)
	claims := unverifiedClaims(t, token)
	if claims["trg"] != "schedule" || claims["automation"] != "au_brief" || claims["sub"] != userID {
		t.Fatalf("firing token: %v", claims)
	}

	// The harness makes its own child, as for voice, and can't shed the trigger.
	if status, body := h.createGrant(piRuntime, map[string]any{
		"subject_token": token, "trigger": "user", "actions": []string{"crm:read"}, "audiences": []string{piRuntime},
	}); status != http.StatusBadRequest {
		t.Errorf("a child changed its trigger: %d %v", status, body)
	}
	harness := h.grant(piRuntime, token, []string{"crm:read"}, []string{piRuntime})
	if claims := unverifiedClaims(t, h.mint(piRuntime, harness)); claims["trg"] != "schedule" || claims["automation"] != "au_brief" {
		t.Fatalf("harness token: %v", claims)
	}

	// Suspending ada stops the firing, the harness's run and the next firing.
	if _, err := h.pool.Exec(context.Background(), "UPDATE auth.users SET status = 'suspended' WHERE id = $1", userID); err != nil {
		t.Fatal(err)
	}
	h.wantStopped(firingRuntime, run)
	h.wantStopped(piRuntime, harness)
	if status, body := h.firing(standing, map[string]any{
		"trigger": "schedule", "automation": "au_brief", "actions": []string{"crm:read"}, "audiences": []string{piRuntime},
	}); status != http.StatusBadRequest {
		t.Errorf("fired for a suspended person: %d %v", status, body)
	}
}

func TestOnlyAutomationsHoldStandingGrants(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	user := h.login("ada", "ten_acme")
	if status, body := h.createGrant(piRuntime, map[string]any{
		"subject_token": user, "standing": true, "actions": []string{"crm:read"}, "audiences": []string{piRuntime},
	}); status != http.StatusBadRequest {
		t.Errorf("a harness held consent: %d %v", status, body)
	}
	// A root names no trigger: a person is present, so it's theirs.
	if status, body := h.createGrant(piRuntime, map[string]any{
		"subject_token": user, "trigger": "schedule", "automation": "au_1", "actions": []string{"crm:read"}, "audiences": []string{piRuntime},
	}); status != http.StatusBadRequest {
		t.Errorf("a root named a trigger: %d %v", status, body)
	}
	root := h.grant(piRuntime, user, []string{"crm:read"}, []string{piRuntime})
	if claims := unverifiedClaims(t, h.mint(piRuntime, root)); claims["trg"] != "user" || claims["automation"] != nil {
		t.Errorf("a person's run: %v", claims)
	}
	calls := newHarness(t, true)
	_, _, call := calls.admitted("ten_acme")
	if claims := unverifiedClaims(t, calls.mint(voiceRuntime, call)); claims["trg"] != "voice" {
		t.Errorf("a call: %v", claims)
	}
}

func TestUsingT10RenewsStandingGrants(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	h.tenant("ten_acme")
	userID := h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	standing := h.standing(h.login("ada", "ten_acme"))
	lapsed := h.standing(h.login("ada", "ten_acme"))
	set := func(id, interval string) {
		if _, err := h.pool.Exec(ctx, "UPDATE auth.agent_grants SET expires_at = now() + $2::interval WHERE id = $1", id, interval); err != nil {
			t.Fatal(err)
		}
	}
	set(standing, "10 days")
	set(lapsed, "-1 hour")
	renew := func() {
		if err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error { return agents.RenewStanding(ctx, tx, userID) }); err != nil {
			t.Fatal(err)
		}
	}
	renew()
	var renewed, still time.Time
	read := func(id string) time.Time {
		var at time.Time
		if err := h.pool.QueryRow(ctx, "SELECT expires_at FROM auth.agent_grants WHERE id = $1", id).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	if renewed = read(standing); time.Until(renewed) < agents.StandingGrantTTL-time.Hour {
		t.Errorf("not renewed: %v left", time.Until(renewed))
	}
	// Lapsed consent needs a person to give it again.
	if still = read(lapsed); still.After(time.Now()) {
		t.Errorf("lapsed consent came back: %v", still)
	}
	// A fresh one isn't written again on every refresh.
	renew()
	if read(standing) != renewed {
		t.Error("renewed again within a day")
	}
}
