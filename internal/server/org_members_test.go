package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"t10-auth-server/internal/directory"
)

func (h *harness) leave(user string) {
	h.t.Helper()
	inactive := directory.MemberInactive
	if _, err := h.dir.UpdateMember(context.Background(), "test", "ten_acme", user, directory.MemberUpdate{Status: &inactive}); err != nil {
		h.t.Fatal(err)
	}
}

func TestDirectReportsAndManagerSkipSomeoneWhoLeft(t *testing.T) {
	h := newHarness(t, true)
	u := h.orgUsers("ceo", "vice", "rep")
	h.mustPlace(u["vice"], u["ceo"], "")
	h.mustPlace(u["rep"], u["vice"], "")
	h.leave(u["vice"])
	service := h.serviceToken(otherService)

	status, body := h.do("GET", "/v1/org/members/"+u["ceo"]+"/reports?tenant=ten_acme", service, nil)
	h.wantStatus(status, body, http.StatusOK)
	if !sameIDs(ids(body), u["rep"]) {
		t.Errorf("direct reports = %v", body)
	}
	status, body = h.do("GET", "/v1/org/members/"+u["rep"]+"?tenant=ten_acme", service, nil)
	h.wantStatus(status, body, http.StatusOK)
	if body["manager_user_id"] != u["ceo"] || body["assigned_manager_user_id"] != u["vice"] {
		t.Errorf("rep = %v", body)
	}

	// Saving the same manager is a unit change, and must not cut the chain.
	if err := h.place(u["rep"], u["vice"], h.unit("Sales", "")); err != nil {
		t.Fatalf("an unchanged departed manager was refused: %v", err)
	}
	active := directory.MemberActive
	if _, err := h.dir.UpdateMember(context.Background(), "test", "ten_acme", u["vice"], directory.MemberUpdate{Status: &active}); err != nil {
		t.Fatal(err)
	}
	status, body = h.do("GET", "/v1/org/members/"+u["rep"]+"?tenant=ten_acme", service, nil)
	h.wantStatus(status, body, http.StatusOK)
	if body["manager_user_id"] != u["vice"] {
		t.Errorf("reinstating the manager did not restore the chain: %v", body)
	}
}

func TestANewDepartedManagerIsStillRefused(t *testing.T) {
	h := newHarness(t, true)
	u := h.orgUsers("gone", "rep")
	h.leave(u["gone"])
	if err := h.place(u["rep"], u["gone"], ""); err == nil {
		t.Error("set a manager who already left")
	}
}

func TestMemberListKeepsADepartedManager(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.user("admin", map[string]string{"ten_acme": directory.RoleAdmin})
	vice := h.user("vice", map[string]string{"ten_acme": directory.RoleMember})
	rep := h.user("rep", map[string]string{"ten_acme": directory.RoleMember})
	h.mustPlace(rep, vice, "")
	h.leave(vice)

	// An admin screen shows the link as set, so saving it back keeps it.
	_, body := h.do("GET", "/v1/tenants/ten_acme/members", h.login("admin", "ten_acme"), nil)
	for _, m := range body["members"].([]any) {
		if row := m.(map[string]any); row["user_id"] == rep && row["manager_user_id"] != vice {
			t.Errorf("the departed manager is missing, so saving the row would erase the link: %v", row)
		}
	}
}

func TestOrgMembersPagesAndKeepsDeparted(t *testing.T) {
	h := newHarness(t, true)
	u := h.orgUsers("anna", "bob", "carl")
	h.leave(u["carl"])
	service := h.serviceToken(otherService)

	seen := map[string]map[string]any{}
	cursor := ""
	for pages := 0; ; pages++ {
		status, body := h.do("GET", "/v1/org/members?tenant=ten_acme&limit=2&cursor="+cursor, service, nil)
		h.wantStatus(status, body, http.StatusOK)
		for _, raw := range body["members"].([]any) {
			m := raw.(map[string]any)
			seen[m["user_id"].(string)] = m
		}
		if cursor = body["next_cursor"].(string); cursor == "" {
			break
		}
		if pages > 3 {
			t.Fatal("paging never ended")
		}
	}
	if len(seen) != 3 || seen[u["carl"]]["status"] != directory.MemberInactive {
		t.Errorf("members = %v", seen)
	}

	status, body := h.do("GET", "/v1/org/members?tenant=ten_acme&status=active", service, nil)
	h.wantStatus(status, body, http.StatusOK)
	if got := len(body["members"].([]any)); got != 2 {
		t.Errorf("active members = %d", got)
	}
}

func TestOrgMembersSearchesDisplayNamesOnly(t *testing.T) {
	h := newHarness(t, true)
	u := h.orgUsers("signin-name", "other")
	if err := h.id.SetDisplayName(context.Background(), u["other"], "100% Grace_Hopper"); err != nil {
		t.Fatal(err)
	}
	service := h.serviceToken(otherService)
	for q, want := range map[string]int{"grace": 1, "signin": 0, "100%25": 1, "x_y": 0, "%25": 1, "_": 1} {
		status, body := h.do("GET", "/v1/org/members?tenant=ten_acme&q="+q, service, nil)
		h.wantStatus(status, body, http.StatusOK)
		if got := len(body["members"].([]any)); got != want {
			t.Errorf("q=%s found %d, want %d", q, got, want)
		}
	}
	if status, body := h.do("GET", "/v1/org/members?tenant=ten_nobody", service, nil); status != http.StatusNotFound {
		t.Errorf("unknown tenant: %d %v", status, body)
	}
	if status, _ := h.do("GET", "/v1/org/members?tenant=ten_acme&limit=501", service, nil); status != http.StatusBadRequest {
		t.Errorf("oversized page: %d", status)
	}
}

func TestPeopleSetTheirOwnDisplayName(t *testing.T) {
	h := newHarness(t, true)
	h.orgUsers("ada")
	token := h.login("ada", "ten_acme")

	status, body := h.do("PATCH", "/v1/me", token, map[string]string{"display_name": "  Ada L  "})
	h.wantStatus(status, body, http.StatusNoContent)
	status, body = h.do("GET", "/v1/me", token, nil)
	h.wantStatus(status, body, http.StatusOK)
	if body["display_name"] != "Ada L" {
		t.Errorf("display_name = %v", body["display_name"])
	}
	for _, bad := range []string{"", "   ", strings.Repeat("x", 101), "a\nb"} {
		if status, _ := h.do("PATCH", "/v1/me", token, map[string]string{"display_name": bad}); status != http.StatusBadRequest {
			t.Errorf("%q: status %d", bad, status)
		}
	}
	if h.auditCount("display_name.change", "success") != 1 {
		t.Error("the change was not audited")
	}
}
