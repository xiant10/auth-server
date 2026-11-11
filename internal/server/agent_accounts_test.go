package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"t10-auth-server/internal/agents"
	"t10-auth-server/internal/directory"
)

// agentAccount creates "Lead desk" in ten_acme as its admin, managed by manager.
func (h *harness) agentAccount(admin, manager string) string {
	h.t.Helper()
	status, body := h.do("POST", "/v1/tenants/ten_acme/agent-accounts", admin, map[string]any{
		"display_name": "Lead desk", "manager_user_id": manager,
	})
	h.wantStatus(status, body, http.StatusCreated)
	if body["kind"] != directory.KindAgent || body["role"] != directory.RoleMember || body["manager_user_id"] != manager {
		h.t.Fatalf("agent account: %v", body)
	}
	return body["user_id"].(string)
}

func TestAgentAccountIsAMemberWithoutASignIn(t *testing.T) {
	h := newHarness(t, true)
	u := h.orgUsers("ada", "bob")
	admin := h.adminToken("ten_acme")
	account := h.agentAccount(admin, u["ada"])

	// Modules see a member like any other, marked as an agent.
	status, body := h.do("GET", "/v1/org/members/"+account+"?tenant=ten_acme", h.serviceToken(otherService), nil)
	h.wantStatus(status, body, http.StatusOK)
	if body["kind"] != directory.KindAgent || body["display_name"] != "Lead desk" || body["manager_user_id"] != u["ada"] {
		t.Errorf("org member: %v", body)
	}
	status, body = h.do("GET", "/v1/me/access", h.login("ada", "ten_acme"), nil)
	h.wantStatus(status, body, http.StatusOK)
	if got, _ := body["managed_agents"].([]any); len(got) != 1 || got[0] != account {
		t.Errorf("ada manages: %v", body)
	}
	status, body = h.do("GET", "/v1/org/members/"+u["ada"]+"/reports?tenant=ten_acme", h.serviceToken(otherService), nil)
	h.wantStatus(status, body, http.StatusOK)
	if !sameIDs(ids(body), account) {
		t.Errorf("ada's reports: %v", body)
	}
	status, body = h.do("GET", "/v1/tenants/ten_acme/members", admin, nil)
	h.wantStatus(status, body, http.StatusOK)
	found := false
	for _, m := range body["members"].([]any) {
		m := m.(map[string]any)
		found = found || (m["user_id"] == account && m["kind"] == directory.KindAgent)
	}
	if !found {
		t.Errorf("admin listing: %v", body)
	}

	// No sign-in, no admin role, no second tenant.
	ctx := context.Background()
	if _, err := h.pool.Exec(ctx, "INSERT INTO auth.user_identifiers (kind, value, user_id) VALUES ('username', 'leaddesk', $1)", account); err == nil {
		t.Error("an agent account got a sign-in name")
	}
	if _, err := h.pool.Exec(ctx, "INSERT INTO auth.credentials (user_id, password_hash) VALUES ($1, 'x')", account); err == nil {
		t.Error("an agent account got a password")
	}
	status, body = h.do("PATCH", "/v1/tenants/ten_acme/members/"+account, admin, map[string]any{"role": "admin"})
	h.wantStatus(status, body, http.StatusBadRequest)
	h.tenant("ten_globex")
	if _, err := h.dir.Add(ctx, "test", "ten_globex", account, directory.RoleMember); err == nil {
		t.Error("an agent account joined a second tenant")
	}

	// A tenant admin renames it; a person's name isn't theirs to change.
	status, body = h.do("PATCH", "/v1/tenants/ten_acme/agent-accounts/"+account, admin, map[string]any{"display_name": "Lead desk 2"})
	h.wantStatus(status, body, http.StatusOK)
	if body["display_name"] != "Lead desk 2" {
		t.Errorf("rename: %v", body)
	}
	status, body = h.do("PATCH", "/v1/tenants/ten_acme/agent-accounts/"+u["bob"], admin, map[string]any{"display_name": "Bobby"})
	h.wantStatus(status, body, http.StatusNotFound)
	status, body = h.do("POST", "/v1/tenants/ten_acme/agent-accounts", admin, map[string]any{"display_name": "  "})
	h.wantStatus(status, body, http.StatusBadRequest)
	if h.auditCount("agent_account.create", "success") != 1 || h.auditCount("agent_account.rename", "success") != 1 {
		t.Error("agent account changes aren't audited")
	}

	// A member can't create one.
	status, body = h.do("POST", "/v1/tenants/ten_acme/agent-accounts", h.login("bob", "ten_acme"), map[string]any{"display_name": "Mine"})
	h.wantStatus(status, body, http.StatusForbidden)
}

func TestAgentAccountManagesNobody(t *testing.T) {
	h := newHarness(t, true)
	u := h.orgUsers("ada", "bob")
	admin := h.adminToken("ten_acme")
	account := h.agentAccount(admin, u["ada"])

	if err := h.place(u["bob"], account, ""); err == nil {
		t.Error("an agent account became a manager")
	}
	status, body := h.do("PUT", "/v1/tenants/ten_acme/placements", admin, map[string]any{
		"placements": []map[string]string{{"user_id": u["bob"], "manager_user_id": account}},
	})
	h.wantStatus(status, body, http.StatusBadRequest)
	unit := h.unit("Sales", "")
	status, body = h.do("PUT", "/v1/tenants/ten_acme/units/"+unit, admin, map[string]any{"name": "Sales", "kind": "department", "lead_user_id": account})
	h.wantStatus(status, body, http.StatusBadRequest)
	// It can still be placed, under a person and in a unit.
	h.mustPlace(account, u["bob"], unit)
}

func TestTenantConsentsForAnAgentAccount(t *testing.T) {
	h := newHarness(t, true)
	u := h.orgUsers("ada")
	admin := h.adminToken("ten_acme")
	account := h.agentAccount(admin, u["ada"])
	req := func(subject string) map[string]any {
		return map[string]any{
			"subject_token": subject, "standing": true, "principal": account,
			"actions": []string{"crm:read"}, "audiences": []string{piRuntime, listedService},
		}
	}

	// Only a tenant admin's live token, only for t10-automations, only for an agent account here.
	status, body := h.createGrant(firingRuntime, req(h.login("ada", "ten_acme")))
	h.wantStatus(status, body, http.StatusForbidden)
	status, body = h.createGrant(piRuntime, req(admin))
	h.wantStatus(status, body, http.StatusBadRequest)
	person := req(admin)
	person["principal"] = u["ada"]
	status, body = h.createGrant(firingRuntime, person)
	h.wantStatus(status, body, http.StatusBadRequest)
	notStanding := req(admin)
	notStanding["standing"] = false
	status, body = h.createGrant(firingRuntime, notStanding)
	h.wantStatus(status, body, http.StatusBadRequest)

	status, body = h.createGrant(firingRuntime, req(admin))
	h.wantStatus(status, body, http.StatusCreated)
	standing := body["id"].(string)
	expires, _ := time.Parse(time.RFC3339Nano, body["expires_at"].(string))
	if body["user_id"] != account || body["given_by"] != h.userID("chief") || time.Until(expires) < agents.StandingGrantTTL*10 {
		t.Fatalf("agent standing grant: %v", body)
	}

	// A firing runs as the account, and the harness's token says so.
	status, body = h.firing(standing, map[string]any{
		"trigger": "event", "automation": "au_intake", "actions": []string{"crm:read"}, "audiences": []string{piRuntime, listedService},
	})
	h.wantStatus(status, body, http.StatusCreated)
	run := body["id"].(string)
	claims := unverifiedClaims(t, h.mint(firingRuntime, run))
	if claims["sub"] != account || claims["trg"] != "event" || claims["tid"] != "ten_acme" {
		t.Fatalf("firing token: %v", claims)
	}

	// The admin who gave it leaving doesn't stop it: it's the tenant's consent.
	h.user("deputy", map[string]string{"ten_acme": directory.RoleAdmin})
	status, body = h.do("PATCH", "/v1/tenants/ten_acme/members/"+h.userID("chief"), h.login("deputy", "ten_acme"), map[string]any{"status": "inactive"})
	h.wantStatus(status, body, http.StatusOK)
	status, body = h.firing(standing, map[string]any{
		"trigger": "event", "automation": "au_intake", "actions": []string{"crm:read"}, "audiences": []string{piRuntime},
	})
	h.wantStatus(status, body, http.StatusCreated)

	// Removing the account ends it, and every run under it.
	status, body = h.do("PATCH", "/v1/tenants/ten_acme/members/"+account, h.login("deputy", "ten_acme"), map[string]any{"status": "inactive"})
	h.wantStatus(status, body, http.StatusOK)
	h.wantStopped(firingRuntime, run)
	status, body = h.firing(standing, map[string]any{
		"trigger": "event", "automation": "au_intake", "actions": []string{"crm:read"}, "audiences": []string{piRuntime},
	})
	h.wantStatus(status, body, http.StatusBadRequest)
}
