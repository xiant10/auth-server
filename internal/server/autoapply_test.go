package server

import (
	"net/http"
	"slices"
	"testing"
)

// chainActions reads a grant's chain as a module does, and answers each link's actions.
func (h *harness) chainActions(grant string) [][]string {
	h.t.Helper()
	status, body := h.do("GET", "/v1/grants/"+grant+"/chain", h.serviceToken(listedService), nil)
	h.wantStatus(status, body, http.StatusOK)
	var out [][]string
	for _, raw := range body["chain"].([]any) {
		var actions []string
		for _, a := range raw.(map[string]any)["actions"].([]any) {
			actions = append(actions, a.(string))
		}
		out = append(out, actions)
	}
	return out
}

func stringList(v any) []string {
	out := []string{}
	for _, s := range v.([]any) {
		out = append(out, s.(string))
	}
	return out
}

func TestAutoApplyIsThePersonsChoicePerTenant(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.tenant("ten_globex")
	h.user("ada", map[string]string{"ten_acme": "member", "ten_globex": "member"})
	acme, globex := h.login("ada", "ten_acme"), h.login("ada", "ten_globex")

	status, body := h.do("GET", "/v1/me/auto-apply", acme, nil)
	h.wantStatus(status, body, http.StatusOK)
	if got := stringList(body["modules"]); len(got) != 0 {
		t.Fatalf("off by default: %v", got)
	}
	status, body = h.do("PUT", "/v1/me/auto-apply", acme, map[string]any{"modules": []string{"work", "crm", "work"}})
	h.wantStatus(status, body, http.StatusOK)
	if got := stringList(body["modules"]); !slices.Equal(got, []string{"crm", "work"}) {
		t.Errorf("saved: %v", got)
	}
	status, body = h.do("GET", "/v1/me/auto-apply", acme, nil)
	h.wantStatus(status, body, http.StatusOK)
	if got := stringList(body["modules"]); !slices.Equal(got, []string{"crm", "work"}) {
		t.Errorf("read back: %v", got)
	}
	status, body = h.do("GET", "/v1/me/auto-apply", globex, nil)
	h.wantStatus(status, body, http.StatusOK)
	if got := stringList(body["modules"]); len(got) != 0 {
		t.Errorf("another tenant: %v", got)
	}
	for _, bad := range []map[string]any{{"modules": []string{"Work"}}, {"modules": []string{"work:apply"}}, {"modules": []string{""}}, {}} {
		if status, body := h.do("PUT", "/v1/me/auto-apply", acme, bad); status != http.StatusBadRequest {
			t.Errorf("%v: %d %v", bad, status, body)
		}
	}
	// Not an agent's, nor a service's, nor anyone's without a token.
	if status, _ := h.do("PUT", "/v1/me/auto-apply", h.serviceToken(listedService), map[string]any{"modules": []string{}}); status != http.StatusUnauthorized && status != http.StatusForbidden {
		t.Errorf("a service token: %d", status)
	}
	if status, _ := h.do("GET", "/v1/me/auto-apply", "", nil); status != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", status)
	}
	// A change is audited, with what it was before.
	var n int
	if err := h.pool.QueryRow(t.Context(), `SELECT count(*) FROM auth.audit_log WHERE action = 'auto_apply.set'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("audited %d times: %v", n, err)
	}
}

func TestChainCarriesApplyOnlyWhileThePersonChoosesIt(t *testing.T) {
	h := newHarness(t, true)
	_, userToken, _ := h.admitted("ten_acme")
	status, body := h.createGrant(piRuntime, map[string]any{
		"subject_token": userToken, "actions": []string{"crm:read", "crm:act", "crm:apply", "deals:apply"}, "audiences": []string{piRuntime, listedService},
	})
	h.wantStatus(status, body, http.StatusCreated)
	root := body["id"].(string)
	// A child keeps what its parent asked for, so it can narrow to apply.
	status, body = h.createGrant(piRuntime, map[string]any{
		"subject_token": h.mint(piRuntime, root), "actions": []string{"crm:read", "crm:apply"}, "audiences": []string{listedService},
	})
	h.wantStatus(status, body, http.StatusCreated)
	child := body["id"].(string)

	holds := func(action string) []bool {
		var out []bool
		for _, link := range h.chainActions(child) {
			out = append(out, slices.Contains(link, action))
		}
		return out
	}
	if got := holds("crm:apply"); !slices.Equal(got, []bool{false, false}) {
		t.Fatalf("not chosen: %v", got)
	}
	if got := holds("crm:read"); !slices.Equal(got, []bool{true, true}) {
		t.Fatalf("other actions: %v", got)
	}
	// Turned on mid-conversation, the live chain carries it, and only for that module.
	status, body = h.do("PUT", "/v1/me/auto-apply", userToken, map[string]any{"modules": []string{"crm"}})
	h.wantStatus(status, body, http.StatusOK)
	if got := holds("crm:apply"); !slices.Equal(got, []bool{true, true}) {
		t.Errorf("chosen: %v", got)
	}
	if root := h.chainActions(root)[0]; !slices.Contains(root, "crm:apply") || slices.Contains(root, "deals:apply") {
		t.Errorf("only the chosen module: %v", root)
	}
	// Turned off, it's gone again.
	status, body = h.do("PUT", "/v1/me/auto-apply", userToken, map[string]any{"modules": []string{}})
	h.wantStatus(status, body, http.StatusOK)
	if got := holds("crm:apply"); !slices.Equal(got, []bool{false, false}) {
		t.Errorf("turned off: %v", got)
	}
}

func TestAnAgentAccountsChainNeverCarriesApply(t *testing.T) {
	h := newHarness(t, true)
	u := h.orgUsers("ada")
	admin := h.adminToken("ten_acme")
	account := h.agentAccount(admin, u["ada"])
	status, body := h.createGrant(firingRuntime, map[string]any{
		"subject_token": admin, "standing": true, "principal": account,
		"actions": []string{"crm:read", "crm:apply"}, "audiences": []string{piRuntime, listedService},
	})
	h.wantStatus(status, body, http.StatusCreated)
	if link := h.chainActions(body["id"].(string))[0]; slices.Contains(link, "crm:apply") || !slices.Contains(link, "crm:read") {
		t.Errorf("an agent account's chain: %v", link)
	}
}

func TestARuntimeWithoutApplyCantAskForIt(t *testing.T) {
	h := newHarness(t, true)
	_, userToken, _ := h.admitted("ten_acme")
	status, body := h.createGrant(gatedRuntime, map[string]any{
		"subject_token": userToken, "actions": []string{"crm:read", "crm:apply"}, "audiences": []string{gatedRuntime},
	})
	h.wantStatus(status, body, http.StatusBadRequest)
}
