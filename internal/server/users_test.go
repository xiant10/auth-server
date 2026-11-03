package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/identity"
)

// platformFixture is adminFixture plus one platform admin with a token.
func platformFixture(t *testing.T) (h *harness, member, root, rootToken string) {
	t.Helper()
	h, member = adminFixture(t, true)
	root = h.user("root", nil)
	h.platformAdmin(root)
	return h, member, root, h.login("root", "")
}

func TestTenantAdminManagesOrgOverJSON(t *testing.T) {
	h, member := adminFixture(t, true)
	token := h.login("boss", "ten_acme")
	const base = "/v1/tenants/ten_acme"

	status, body := h.do("POST", base+"/units", token, map[string]string{"name": " Sales ", "kind": "department"})
	h.wantStatus(status, body, http.StatusCreated)
	sales := body["id"].(string)
	if body["name"] != "Sales" {
		t.Errorf("created unit: %v", body)
	}
	status, body = h.do("POST", base+"/units", token, map[string]string{"name": "East", "kind": "team", "parent_id": sales})
	h.wantStatus(status, body, http.StatusCreated)
	east := body["id"].(string)

	status, body = h.do("PUT", base+"/units/"+east, token, map[string]string{"name": "EMEA", "kind": "team", "parent_id": sales})
	h.wantStatus(status, body, http.StatusOK)
	if body["name"] != "EMEA" || body["parent_id"] != sales {
		t.Errorf("updated unit: %v", body)
	}
	status, body = h.do("GET", base+"/units", token, nil)
	h.wantStatus(status, body, http.StatusOK)
	units := body["units"].([]any)
	if len(units) != 2 || units[1].(map[string]any)["name"] != "EMEA" {
		t.Errorf("units: %v", units)
	}

	status, body = h.do("PUT", base+"/units/"+sales, token, map[string]string{"name": "Sales", "kind": "department", "parent_id": east})
	h.wantStatus(status, body, http.StatusConflict)
	if body["error"] != "cycle" {
		t.Errorf("unit cycle: %v", body)
	}
	status, body = h.do("PUT", base+"/units/"+east, token, map[string]string{"name": "EMEA", "kind": "squad"})
	h.wantStatus(status, body, http.StatusBadRequest)
	status, body = h.do("PUT", base+"/units/"+east, token, map[string]string{"name": "EMEA", "kind": "team", "parent": sales})
	h.wantStatus(status, body, http.StatusBadRequest)
	status, body = h.do("PUT", base+"/units/org_missing", token, map[string]string{"name": "EMEA", "kind": "team"})
	h.wantStatus(status, body, http.StatusNotFound)

	boss := h.userID("boss")
	status, body = h.do("PUT", base+"/members/"+member+"/placement", token, map[string]string{"manager_user_id": boss, "org_unit_id": east})
	h.wantStatus(status, body, http.StatusOK)
	if body["manager_user_id"] != boss || body["org_unit_id"] != east || body["user_status"] != "active" {
		t.Errorf("placement: %v", body)
	}
	status, body = h.do("GET", base+"/members/"+member+"/placement", token, nil)
	h.wantStatus(status, body, http.StatusOK)
	if body["manager_user_id"] != boss {
		t.Errorf("read placement: %v", body)
	}
	status, body = h.do("PUT", base+"/members/"+boss+"/placement", token, map[string]string{"manager_user_id": member})
	h.wantStatus(status, body, http.StatusConflict)
	if body["error"] != "cycle" {
		t.Errorf("manager cycle: %v", body)
	}

	status, body = h.do("DELETE", base+"/units/"+east, token, nil)
	h.wantStatus(status, body, http.StatusConflict)
	if body["error"] != "unit_in_use" {
		t.Errorf("unit in use: %v", body)
	}
	// A PUT replaces the placement, so an empty one clears both fields.
	status, body = h.do("PUT", base+"/members/"+member+"/placement", token, map[string]string{})
	h.wantStatus(status, body, http.StatusOK)
	if body["manager_user_id"] != nil || body["org_unit_id"] != nil {
		t.Errorf("cleared placement: %v", body)
	}
	if status, _ := h.do("DELETE", base+"/units/"+east, token, nil); status != http.StatusNoContent {
		t.Errorf("delete: %d", status)
	}
	if h.auditCount("org_unit.update", "success") != 1 || h.auditCount("org_unit.delete", "success") != 1 || h.auditCount("membership.placement", "success") != 2 {
		t.Error("JSON org writes aren't audited")
	}
}

func TestJSONOrgWritesStayInTheTokensTenant(t *testing.T) {
	h, member, _, rootToken := platformFixture(t)
	acme, err := h.dir.CreateUnit(context.Background(), "test", "ten_acme", "Sales", directory.UnitTeam, "")
	if err != nil {
		t.Fatal(err)
	}
	other, err := h.dir.CreateUnit(context.Background(), "test", "ten_other", "Rivals", directory.UnitTeam, "")
	if err != nil {
		t.Fatal(err)
	}
	const base = "/v1/tenants/ten_acme"
	unit := map[string]string{"name": "x", "kind": "team"}
	writes := []struct {
		method, path string
		body         any
	}{
		{"GET", base + "/units", nil},
		{"POST", base + "/units", unit},
		{"PUT", base + "/units/" + acme.ID, unit},
		{"DELETE", base + "/units/" + acme.ID, nil},
		{"GET", base + "/members/" + member + "/placement", nil},
		{"PUT", base + "/members/" + member + "/placement", map[string]string{}},
	}
	for name, token := range map[string]string{"member": h.login("grace", "ten_acme"), "other tenant's admin": h.login("rival", "ten_other")} {
		for _, w := range writes {
			if status, _ := h.do(w.method, w.path, token, w.body); status != http.StatusForbidden {
				t.Errorf("%s: %s %s = %d", name, w.method, w.path, status)
			}
		}
	}
	if status, _ := h.do("GET", base+"/units", "", nil); status != http.StatusUnauthorized {
		t.Errorf("no token: %d", status)
	}
	if status, body := h.do("GET", base+"/units", rootToken, nil); status != http.StatusOK {
		t.Errorf("platform admin: %d %v", status, body)
	}

	// IDs from another tenant look like IDs that don't exist.
	token := h.login("boss", "ten_acme")
	status, body := h.do("POST", base+"/units", token, map[string]string{"name": "x", "kind": "team", "parent_id": other.ID})
	h.wantStatus(status, body, http.StatusNotFound)
	status, body = h.do("PUT", "/v1/tenants/ten_acme/units/"+other.ID, token, unit)
	h.wantStatus(status, body, http.StatusNotFound)
	status, body = h.do("PUT", base+"/members/"+member+"/placement", token, map[string]string{"org_unit_id": other.ID})
	h.wantStatus(status, body, http.StatusNotFound)
	status, body = h.do("PUT", base+"/members/"+member+"/placement", token, map[string]string{"manager_user_id": h.userID("rival")})
	h.wantStatus(status, body, http.StatusBadRequest)
}

func TestSuspensionStopsEveryWayIn(t *testing.T) {
	h := newHarness(t, true)
	userID, token, grantID := h.admitted("ten_acme")
	root := h.user("root", nil)
	h.platformAdmin(root)
	rootToken := h.login("root", "")
	browser := h.signedIn("ada")
	a := h.app()
	a.login("ada")

	status, body := h.do("POST", "/v1/users/"+userID+"/suspend", rootToken, nil)
	h.wantStatus(status, body, http.StatusOK)

	if status, _ := h.do("GET", "/v1/me", token, nil); status != http.StatusUnauthorized {
		t.Errorf("token still works: %d", status)
	}
	if status, _, _ := browser.get("/v1/account"); status != http.StatusSeeOther {
		t.Errorf("browser still signed in: %d", status)
	}
	if status, _ := a.tryRefresh("ten_acme"); status == http.StatusOK {
		t.Error("device session still refreshes")
	}
	if status, _ := a.tryLogin("ada", testPassword); status == http.StatusOK {
		t.Error("app can still log in")
	}
	if status := h.browser().signIn("ada", testPassword, ""); status == http.StatusSeeOther {
		t.Error("browser can still sign in")
	}
	h.wantStopped(voiceRuntime, grantID)
	if h.auditCount("user.status", "success") != 1 {
		t.Error("suspension isn't audited")
	}

	status, body = h.do("POST", "/v1/users/"+userID+"/activate", rootToken, nil)
	h.wantStatus(status, body, http.StatusOK)
	if status, _ := h.do("GET", "/v1/me", token, nil); status != http.StatusUnauthorized {
		t.Errorf("reactivating revived a session: %d", status)
	}
	h.wantStopped(voiceRuntime, grantID)
	if status, _ := h.do("GET", "/v1/me", h.login("ada", ""), nil); status != http.StatusOK {
		t.Errorf("sign-in after reactivating: %d", status)
	}
}

func TestSuspensionIsForPlatformAdminsOnly(t *testing.T) {
	h, member, root, rootToken := platformFixture(t)
	for name, token := range map[string]string{"tenant admin": h.login("boss", "ten_acme"), "member": h.login("grace", "ten_acme")} {
		for _, w := range [][2]string{
			{"GET", "/v1/users"}, {"POST", "/v1/users/" + member + "/suspend"}, {"POST", "/v1/users/" + member + "/activate"},
			{"PUT", "/v1/users/" + member + "/platform-admin"}, {"DELETE", "/v1/users/" + root + "/platform-admin"},
		} {
			if status, _ := h.do(w[0], w[1], token, nil); status != http.StatusForbidden {
				t.Errorf("%s: %s %s = %d", name, w[0], w[1], status)
			}
		}
	}
	// A denied user action is the platform's, not a tenant named after a user.
	var scope string
	err := h.pool.QueryRow(context.Background(),
		"SELECT scope FROM auth.audit_log WHERE outcome = 'denied' ORDER BY id DESC LIMIT 1").Scan(&scope)
	if err != nil || strings.Contains(scope, "usr_") {
		t.Errorf("denied scope = %q, %v", scope, err)
	}

	status, body := h.do("POST", "/v1/users/usr_missing/suspend", rootToken, nil)
	h.wantStatus(status, body, http.StatusNotFound)
	status, body = h.do("POST", "/v1/users/"+root+"/suspend", rootToken, nil)
	h.wantStatus(status, body, http.StatusConflict)
	if body["error"] != "platform_admin" {
		t.Errorf("suspending a platform admin: %v", body)
	}
	status, body = h.do("GET", "/v1/users?q=GRA", rootToken, nil)
	h.wantStatus(status, body, http.StatusOK)
	users := body["users"].([]any)
	if len(users) != 1 || users[0].(map[string]any)["id"] != member {
		t.Errorf("search: %v", users)
	}
	status, body = h.do("GET", "/v1/users?q="+member, rootToken, nil)
	h.wantStatus(status, body, http.StatusOK)
	if len(body["users"].([]any)) != 1 {
		t.Errorf("search by ID: %v", body)
	}
}

func TestPlatformRoleGrantAndRemoval(t *testing.T) {
	h, member, root, rootToken := platformFixture(t)
	path := "/v1/users/" + member + "/platform-admin"
	token := h.login("grace", "ten_acme")
	if status, _ := h.do("POST", "/v1/tenants", token, map[string]string{"name": "New"}); status != http.StatusForbidden {
		t.Fatalf("before the grant: %d", status)
	}

	status, body := h.do("PUT", path, rootToken, nil)
	h.wantStatus(status, body, http.StatusOK)
	status, body = h.do("PUT", path, rootToken, nil)
	h.wantStatus(status, body, http.StatusConflict)
	status, body = h.do("PUT", "/v1/users/usr_missing/platform-admin", rootToken, nil)
	h.wantStatus(status, body, http.StatusNotFound)
	status, body = h.do("POST", "/v1/tenants", token, map[string]string{"name": "New"})
	h.wantStatus(status, body, http.StatusCreated)

	status, body = h.do("DELETE", path, rootToken, nil)
	h.wantStatus(status, body, http.StatusOK)
	if status, _ := h.do("POST", "/v1/tenants", token, map[string]string{"name": "Newer"}); status != http.StatusForbidden {
		t.Errorf("a token kept the role after removal: %d", status)
	}
	status, body = h.do("DELETE", path, rootToken, nil)
	h.wantStatus(status, body, http.StatusNotFound)

	status, body = h.do("DELETE", "/v1/users/"+root+"/platform-admin", rootToken, nil)
	h.wantStatus(status, body, http.StatusConflict)
	if body["error"] != "last_platform_admin" {
		t.Errorf("removing the last admin: %v", body)
	}
	if h.auditCount("platform_admin.grant", "success") != 2 || h.auditCount("platform_admin.remove", "success") != 1 {
		t.Error("role changes aren't audited")
	}

	status, body = h.do("POST", "/v1/users/"+member+"/suspend", rootToken, nil)
	h.wantStatus(status, body, http.StatusOK)
	status, body = h.do("PUT", path, rootToken, nil)
	h.wantStatus(status, body, http.StatusConflict)
	if body["error"] != "user_suspended" {
		t.Errorf("granting to a suspended user: %v", body)
	}
}

func TestTwoPlatformAdminsCannotRemoveEachOther(t *testing.T) {
	h, member, root, _ := platformFixture(t)
	h.platformAdmin(member)
	for range 10 {
		var wg sync.WaitGroup
		for _, target := range []string{root, member} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := h.dir.RemovePlatformAdmin(context.Background(), "test", target); err != nil && !errors.Is(err, directory.ErrLastPlatformAdmin) {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		var left int
		if err := h.pool.QueryRow(context.Background(), "SELECT count(*) FROM auth.platform_admins").Scan(&left); err != nil || left != 1 {
			t.Fatalf("%d platform admins left, %v", left, err)
		}
		// Whoever went comes back for the next round.
		for _, target := range []string{root, member} {
			if err := h.dir.AddPlatformAdmin(context.Background(), "test", target); err != nil && !errors.Is(err, directory.ErrExists) {
				t.Fatal(err)
			}
		}
	}
}

func TestGrantAndSuspensionCannotBothWin(t *testing.T) {
	h, member, _, _ := platformFixture(t)
	ctx := context.Background()
	for range 10 {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := h.dir.AddPlatformAdmin(ctx, "test", member); err != nil && !errors.Is(err, directory.ErrUserSuspended) {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			if err := h.id.SetUserStatus(ctx, "test", member, identity.UserSuspended); err != nil && !errors.Is(err, identity.ErrPlatformAdminUser) {
				t.Error(err)
			}
		}()
		wg.Wait()
		var both bool
		err := h.pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM auth.platform_admins a JOIN auth.users u ON u.id = a.user_id WHERE u.status = 'suspended')`).Scan(&both)
		if err != nil || both {
			t.Fatalf("suspended platform admin: %v", err)
		}
		if err := h.id.SetUserStatus(ctx, "test", member, identity.UserActive); err != nil {
			t.Fatal(err)
		}
		if err := h.dir.RemovePlatformAdmin(ctx, "test", member); err != nil && !errors.Is(err, directory.ErrNotFound) {
			t.Fatal(err)
		}
	}
}

func TestSuspendedUsersLeaveTheOrg(t *testing.T) {
	h := newHarness(t, true)
	u := h.orgUsers("boss", "lead", "worker")
	unit := h.unit("Sales", "")
	h.mustPlace(u["lead"], u["boss"], unit)
	h.mustPlace(u["worker"], u["lead"], unit)
	ctx := context.Background()
	if err := h.id.SetUserStatus(ctx, "test", u["lead"], identity.UserSuspended); err != nil {
		t.Fatal(err)
	}
	service := h.serviceToken(otherService)

	_, body := h.do("GET", "/v1/org/members/"+u["boss"]+"/reports?tenant=ten_acme&transitive=true", service, nil)
	if !sameIDs(ids(body), u["worker"]) {
		t.Errorf("reports walk through a suspended manager and omit them: %v", body)
	}
	_, body = h.do("GET", "/v1/org/units/"+unit+"/members?tenant=ten_acme", service, nil)
	if !sameIDs(ids(body), u["worker"]) {
		t.Errorf("unit members: %v", body)
	}
	_, body = h.do("GET", "/v1/org/members/"+u["lead"]+"?tenant=ten_acme", service, nil)
	if body["user_status"] != "suspended" {
		t.Errorf("member: %v", body)
	}
	units, err := h.dir.ListUnits(ctx, "ten_acme")
	if err != nil || units[0].Members != 1 {
		t.Errorf("unit count: %v %v", units, err)
	}
	if err := h.place(u["boss"], u["lead"], ""); !errors.Is(err, directory.ErrInvalid) {
		t.Errorf("a suspended manager: %v", err)
	}
}

func TestSuspendedAdminDoesNotCountAsCover(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	first := h.user("first", map[string]string{"ten_acme": directory.RoleAdmin})
	second := h.user("second", map[string]string{"ten_acme": directory.RoleAdmin})
	ctx := context.Background()
	if err := h.id.SetUserStatus(ctx, "test", second, identity.UserSuspended); err != nil {
		t.Fatal(err)
	}
	role := directory.RoleMember
	_, err := h.dir.UpdateMember(ctx, "test", "ten_acme", first, directory.MemberUpdate{Role: &role})
	if !errors.Is(err, directory.ErrLastAdmin) {
		t.Errorf("demoting the only admin who can sign in: %v", err)
	}
}
