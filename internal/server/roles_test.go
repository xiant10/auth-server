package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"t10-auth-server/internal/roles"
)

// dealsModule is a module whose service is otherService. Version 2 changes the
// rep template, so tests can show a template update changes no role.
func dealsModule(version int, writeLifecycle string) roles.Module {
	rep := []string{"deals:read"}
	if writeLifecycle == roles.LifecycleActive {
		rep = append(rep, "deals:write")
	}
	if version > 1 {
		rep = append(rep, "deals:admin")
	}
	return roles.Module{
		ID: "deals", Prefix: "deals", Service: otherService, Version: version,
		Permissions: []roles.Permission{
			{Key: "deals:read", Description: "See deals", Lifecycle: roles.LifecycleActive},
			{Key: "deals:write", Description: "Change deals", Lifecycle: writeLifecycle},
			{Key: "deals:admin", Description: "Deals settings", Lifecycle: roles.LifecycleActive},
			{Key: "deals:old", Description: "Old", Lifecycle: roles.LifecycleDeprecated},
		},
		Templates: []roles.Template{{ID: "rep", Name: "Sales rep", Permissions: rep}},
	}
}

func crmModule() roles.Module {
	return roles.Module{
		ID: "crm", Prefix: "crm", Service: listedService, Version: 1,
		Permissions: []roles.Permission{
			{Key: "crm:read", Lifecycle: roles.LifecycleActive},
			{Key: "crm:write", Lifecycle: roles.LifecycleActive},
		},
	}
}

func catalogOf(t *testing.T, modules ...roles.Module) *roles.Catalog {
	t.Helper()
	c, err := roles.NewCatalog(modules)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testCatalog(t *testing.T, version int) *roles.Catalog {
	return catalogOf(t, dealsModule(version, roles.LifecycleActive), crmModule())
}

// deploy swaps the catalog the running server reads, as a redeploy with a
// changed overlay would.
func (h *harness) deploy(c *roles.Catalog) {
	h.t.Helper()
	svc := roles.NewService(h.pool, c)
	if err := svc.Sync(context.Background()); err != nil {
		h.t.Fatal(err)
	}
	h.srv.Roles = svc
}

type rolesFixture struct {
	*harness
	admin string
	users map[string]string
}

// newRolesFixture is tenant ten_acme with an admin, boss, and members ana and
// ben, plus ten_other with its own admin, eve.
func newRolesFixture(t *testing.T) rolesFixture {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.tenant("ten_other")
	users := map[string]string{
		"boss": h.user("boss", map[string]string{"ten_acme": "admin"}),
		"ana":  h.user("ana", map[string]string{"ten_acme": "member"}),
		"ben":  h.user("ben", map[string]string{"ten_acme": "member"}),
		"eve":  h.user("eve", map[string]string{"ten_other": "admin"}),
	}
	return rolesFixture{harness: h, admin: h.login("boss", "ten_acme"), users: users}
}

func (f rolesFixture) createRole(body map[string]any) map[string]any {
	f.t.Helper()
	status, out := f.do("POST", "/v1/tenants/ten_acme/roles", f.admin, body)
	f.wantStatus(status, out, http.StatusCreated)
	return out
}

func (f rolesFixture) assign(user string, role map[string]any) string {
	f.t.Helper()
	status, out := f.do("POST", "/v1/tenants/ten_acme/members/"+f.users[user]+"/role-assignments", f.admin,
		map[string]any{"role_id": role["id"]})
	f.wantStatus(status, out, http.StatusCreated)
	return out["id"].(string)
}

func (f rolesFixture) entitlements(service, module string, users ...string) (int, map[string]any) {
	f.t.Helper()
	q := url.Values{"tenant": {"ten_acme"}, "module": {module}}
	for _, u := range users {
		q.Add("user", f.users[u])
	}
	return f.do("GET", "/v1/entitlements?"+q.Encode(), f.serviceToken(service), nil)
}

// grants returns a user's grants as "permission@assignment".
func (f rolesFixture) grants(module, user string) []string {
	f.t.Helper()
	service := map[string]string{"deals": otherService, "crm": listedService}[module]
	status, body := f.entitlements(service, module, user)
	f.wantStatus(status, body, http.StatusOK)
	for _, u := range body["users"].([]any) {
		u := u.(map[string]any)
		if u["user_id"] != f.users[user] {
			continue
		}
		out := []string{}
		for _, g := range u["grants"].([]any) {
			g := g.(map[string]any)
			out = append(out, fmt.Sprint(g["permission"], "@", g["assignment_id"]))
		}
		return out
	}
	f.t.Fatalf("no entry for %s: %v", user, body)
	return nil
}

func (f rolesFixture) revision() float64 {
	f.t.Helper()
	status, body := f.entitlements(otherService, "deals", "ana")
	f.wantStatus(status, body, http.StatusOK)
	return body["revision"].(float64)
}

func strs(v any) []string {
	out := []string{}
	for _, item := range v.([]any) {
		out = append(out, item.(string))
	}
	return out
}

func TestRoleFromTemplateGrantsWithProvenance(t *testing.T) {
	f := newRolesFixture(t)
	role := f.createRole(map[string]any{"template": map[string]string{"module": "deals", "id": "rep"}})
	if role["name"] != "Sales rep" || !slices.Equal(strs(role["permissions"]), []string{"deals:read", "deals:write"}) {
		t.Fatalf("role: %v", role)
	}
	assignment := f.assign("ana", role)

	got := f.grants("deals", "ana")
	want := []string{"deals:read@" + assignment, "deals:write@" + assignment}
	if !slices.Equal(got, want) {
		t.Errorf("grants = %v, want %v", got, want)
	}
	if got := f.grants("deals", "ben"); len(got) != 0 {
		t.Errorf("ben holds %v", got)
	}

	token := f.login("ana", "ten_acme")
	status, access := f.do("GET", "/v1/me/access", token, nil)
	f.wantStatus(status, access, http.StatusOK)
	if !slices.Equal(strs(access["modules"]), []string{"deals"}) || len(strs(access["module_admin"])) != 0 {
		t.Errorf("access: %v", access)
	}
	status, mine := f.do("GET", "/v1/me/permissions?module=deals", token, nil)
	f.wantStatus(status, mine, http.StatusOK)
	if len(mine["grants"].([]any)) != 2 {
		t.Errorf("me/permissions: %v", mine)
	}
	if f.auditCount("role.create", "success") != 1 || f.auditCount("role_assignment.create", "success") != 1 {
		t.Error("role changes weren't audited")
	}
}

func TestTenantAdminAdministersEveryModuleButHoldsNoGrants(t *testing.T) {
	f := newRolesFixture(t)
	status, access := f.do("GET", "/v1/me/access", f.admin, nil)
	f.wantStatus(status, access, http.StatusOK)
	if !slices.Equal(strs(access["module_admin"]), []string{"crm", "deals"}) {
		t.Errorf("module_admin: %v", access)
	}
	status, body := f.entitlements(otherService, "deals", "boss")
	f.wantStatus(status, body, http.StatusOK)
	boss := body["users"].([]any)[0].(map[string]any)
	if boss["tenant_admin"] != true || len(boss["grants"].([]any)) != 0 {
		t.Errorf("boss: %v", boss)
	}
}

func TestModuleAdminPermission(t *testing.T) {
	f := newRolesFixture(t)
	f.assign("ana", f.createRole(map[string]any{"name": "Deals ops", "permissions": []string{"deals:admin"}}))
	status, access := f.do("GET", "/v1/me/access", f.login("ana", "ten_acme"), nil)
	f.wantStatus(status, access, http.StatusOK)
	if !slices.Equal(strs(access["module_admin"]), []string{"deals"}) || access["tenant_admin"] != false {
		t.Errorf("access: %v", access)
	}
}

func TestRoleNameConfersNothing(t *testing.T) {
	f := newRolesFixture(t)
	f.assign("ana", f.createRole(map[string]any{"name": "Admin", "permissions": []string{"deals:read"}}))
	token := f.login("ana", "ten_acme")
	status, access := f.do("GET", "/v1/me/access", token, nil)
	f.wantStatus(status, access, http.StatusOK)
	if access["tenant_admin"] != false {
		t.Errorf("a role named Admin made ana a tenant admin: %v", access)
	}
	for _, path := range []string{"/v1/tenants/ten_acme/roles", "/v1/tenants/ten_acme/members"} {
		if status, _ := f.do("GET", path, token, nil); status != http.StatusForbidden {
			t.Errorf("%s: %d", path, status)
		}
	}
	if status, _ := f.do("POST", "/v1/tenants/ten_acme/roles", token, map[string]any{"name": "x"}); status != http.StatusForbidden {
		t.Errorf("member created a role: %d", status)
	}
}

func TestOnlyOfferedPermissionsCanBeAdded(t *testing.T) {
	f := newRolesFixture(t)
	for _, key := range []string{"deals:nope", "deals:old", "property:read", "crm:delete", "admin"} {
		status, body := f.do("POST", "/v1/tenants/ten_acme/roles", f.admin, map[string]any{"name": "R " + key, "permissions": []string{key}})
		if status != http.StatusBadRequest || body["error"] != "unknown_permission" {
			t.Errorf("%s: %d %v", key, status, body)
		}
	}
	status, body := f.do("POST", "/v1/tenants/ten_acme/roles", f.admin,
		map[string]any{"template": map[string]string{"module": "deals", "id": "nope"}})
	h := f.harness
	h.wantStatus(status, body, http.StatusBadRequest)
	f.createRole(map[string]any{"name": "Unique", "permissions": []string{}})
	status, body = f.do("POST", "/v1/tenants/ten_acme/roles", f.admin, map[string]any{"name": "unique"})
	h.wantStatus(status, body, http.StatusConflict)
}

func TestEntitlementsAreTheServicesOwnNamespace(t *testing.T) {
	f := newRolesFixture(t)
	status, body := f.entitlements(listedService, "deals", "ana")
	f.wantStatus(status, body, http.StatusForbidden)
	status, body = f.entitlements(otherService, "property", "ana")
	f.wantStatus(status, body, http.StatusNotFound)
	q := "/v1/entitlements?tenant=ten_acme&module=deals&user=" + f.users["ana"]
	if status, _ := f.do("GET", q, f.login("ana", "ten_acme"), nil); status != http.StatusUnauthorized {
		t.Errorf("user token: %d", status)
	}
	status, body = f.do("GET", "/v1/entitlements?tenant=ten_acme&module=deals", f.serviceToken(otherService), nil)
	f.wantStatus(status, body, http.StatusBadRequest)
}

func TestScopeStaysWithItsAssignment(t *testing.T) {
	f := newRolesFixture(t)
	support := f.assign("ana", f.createRole(map[string]any{"name": "Support", "permissions": []string{"deals:read"}}))
	rep := f.assign("ana", f.createRole(map[string]any{"name": "Rep", "permissions": []string{"deals:read", "deals:write"}}))
	got := f.grants("deals", "ana")
	want := []string{"deals:read@" + min(support, rep), "deals:read@" + max(support, rep), "deals:write@" + rep}
	if !slices.Equal(got, want) {
		t.Errorf("grants = %v, want %v", got, want)
	}
}

func TestStaleRevisionsAreRefused(t *testing.T) {
	f := newRolesFixture(t)
	role := f.createRole(map[string]any{"name": "Rep", "permissions": []string{"deals:read"}})
	path := "/v1/tenants/ten_acme/roles/" + role["id"].(string)
	status, body := f.do("PATCH", path, f.admin, map[string]any{"revision": role["revision"], "name": "Rep 2"})
	f.wantStatus(status, body, http.StatusOK)
	status, body = f.do("PATCH", path, f.admin, map[string]any{"revision": role["revision"], "name": "Rep 3"})
	if status != http.StatusConflict || body["error"] != "stale_revision" {
		t.Errorf("stale edit: %d %v", status, body)
	}
	status, body = f.do("PATCH", path, f.admin, map[string]any{"name": "Rep 4"})
	f.wantStatus(status, body, http.StatusBadRequest)

	assignment := f.assign("ana", role)
	base := "/v1/tenants/ten_acme/members/" + f.users["ana"] + "/role-assignments/" + assignment
	status, body = f.do("DELETE", base+"?revision=7", f.admin, nil)
	f.wantStatus(status, body, http.StatusConflict)
	status, body = f.do("DELETE", base+"?revision=1", f.admin, nil)
	f.wantStatus(status, body, http.StatusNoContent)
	status, body = f.do("DELETE", base+"?revision=1", f.admin, nil)
	f.wantStatus(status, body, http.StatusConflict)
}

func TestDisableRevokeAndDeactivateStopGrantsAtOnce(t *testing.T) {
	f := newRolesFixture(t)
	role := f.createRole(map[string]any{"name": "Rep", "permissions": []string{"deals:read"}})
	assignment := f.assign("ana", role)
	start := f.revision()

	path := "/v1/tenants/ten_acme/roles/" + role["id"].(string)
	status, body := f.do("PATCH", path, f.admin, map[string]any{"revision": role["revision"], "enabled": false})
	f.wantStatus(status, body, http.StatusOK)
	if got := f.grants("deals", "ana"); len(got) != 0 {
		t.Errorf("disabled role still grants %v", got)
	}
	status, out := f.do("POST", "/v1/tenants/ten_acme/members/"+f.users["ben"]+"/role-assignments", f.admin, map[string]any{"role_id": role["id"]})
	if status != http.StatusConflict || out["error"] != "role_disabled" {
		t.Errorf("assigned a disabled role: %d %v", status, out)
	}
	status, body = f.do("PATCH", path, f.admin, map[string]any{"revision": body["revision"], "enabled": true})
	f.wantStatus(status, body, http.StatusOK)
	if got := f.grants("deals", "ana"); len(got) != 1 {
		t.Errorf("re-enabled role grants %v", got)
	}

	status, body = f.do("PATCH", "/v1/tenants/ten_acme/members/"+f.users["ana"], f.admin, map[string]any{"status": "inactive"})
	f.wantStatus(status, body, http.StatusOK)
	_, ent := f.entitlements(otherService, "deals", "ana")
	ana := ent["users"].([]any)[0].(map[string]any)
	if ana["active"] != false || len(ana["grants"].([]any)) != 0 {
		t.Errorf("deactivated member: %v", ana)
	}
	status, body = f.do("PATCH", "/v1/tenants/ten_acme/members/"+f.users["ana"], f.admin, map[string]any{"status": "active"})
	f.wantStatus(status, body, http.StatusOK)

	status, body = f.do("DELETE", "/v1/tenants/ten_acme/members/"+f.users["ana"]+"/role-assignments/"+assignment+"?revision=1", f.admin, nil)
	f.wantStatus(status, body, http.StatusNoContent)
	if got := f.grants("deals", "ana"); len(got) != 0 {
		t.Errorf("revoked assignment still grants %v", got)
	}
	if end := f.revision(); end != start+5 {
		t.Errorf("revision went from %v to %v, want five raises", start, end)
	}
	again := f.assign("ana", role)
	if again == assignment {
		t.Error("assigning again reused the revoked assignment's ID")
	}
}

func TestRolesStayInTheirTenant(t *testing.T) {
	f := newRolesFixture(t)
	role := f.createRole(map[string]any{"name": "Rep", "permissions": []string{"deals:read"}})
	eve := f.login("eve", "ten_other")
	if status, _ := f.do("GET", "/v1/tenants/ten_acme/roles/"+role["id"].(string), eve, nil); status != http.StatusForbidden {
		t.Errorf("eve read acme's role: %d", status)
	}
	status, body := f.do("GET", "/v1/tenants/ten_other/roles/"+role["id"].(string), eve, nil)
	f.wantStatus(status, body, http.StatusNotFound)
	status, body = f.do("POST", "/v1/tenants/ten_other/members/"+f.users["eve"]+"/role-assignments", eve, map[string]any{"role_id": role["id"]})
	f.wantStatus(status, body, http.StatusNotFound)
	status, body = f.do("POST", "/v1/tenants/ten_acme/members/"+f.users["eve"]+"/role-assignments", f.admin, map[string]any{"role_id": role["id"]})
	f.wantStatus(status, body, http.StatusNotFound)
}

func TestModuleLeavingKeepsRolesAndComingBackRestoresThem(t *testing.T) {
	f := newRolesFixture(t)
	role := f.createRole(map[string]any{"name": "Rep", "permissions": []string{"deals:read", "crm:read"}})
	assignment := f.assign("ana", role)

	f.deploy(catalogOf(t, dealsModule(1, roles.LifecycleActive)))
	if got := f.grants("deals", "ana"); !slices.Equal(got, []string{"deals:read@" + assignment}) {
		t.Errorf("deals grants: %v", got)
	}
	status, body := f.entitlements(listedService, "crm", "ana")
	f.wantStatus(status, body, http.StatusNotFound)
	status, body = f.do("GET", "/v1/tenants/ten_acme/roles/"+role["id"].(string), f.admin, nil)
	f.wantStatus(status, body, http.StatusOK)
	if !slices.Equal(strs(body["unavailable"]), []string{"crm:read"}) || body["active"] != true {
		t.Errorf("role while crm is gone: %v", body)
	}
	status, view := f.do("GET", "/v1/tenants/ten_acme/permission-catalog", f.admin, nil)
	f.wantStatus(status, view, http.StatusOK)
	unavailable := view["unavailable"].([]any)
	if len(unavailable) != 1 || unavailable[0].(map[string]any)["reason"] != "module_not_deployed" {
		t.Errorf("catalog view: %v", view)
	}

	path := "/v1/tenants/ten_acme/roles/" + role["id"].(string)
	status, body = f.do("PATCH", path, f.admin, map[string]any{"revision": body["revision"], "permissions": []string{"deals:read", "crm:read", "deals:admin"}})
	f.wantStatus(status, body, http.StatusOK)
	status, out := f.do("PATCH", path, f.admin, map[string]any{"revision": body["revision"], "permissions": []string{"deals:read", "crm:read", "crm:write"}})
	if status != http.StatusBadRequest || out["error"] != "unknown_permission" {
		t.Errorf("added a permission of a module not deployed: %d %v", status, out)
	}

	f.deploy(testCatalog(t, 1))
	if got := f.grants("crm", "ana"); !slices.Equal(got, []string{"crm:read@" + assignment}) {
		t.Errorf("crm grants after redeploy: %v", got)
	}
}

func TestPurgeRemovesOnlyThatModule(t *testing.T) {
	f := newRolesFixture(t)
	role := f.createRole(map[string]any{"name": "Rep", "permissions": []string{"deals:read", "crm:read"}})
	assignment := f.assign("ana", role)
	if _, err := f.srv.Roles.Purge(context.Background(), "test", "crm"); err != roles.ErrDeployed {
		t.Fatalf("purged a deployed module: %v", err)
	}

	f.deploy(catalogOf(t, dealsModule(1, roles.LifecycleActive)))
	removed, err := f.srv.Roles.Purge(context.Background(), "test", "crm")
	if err != nil || removed != 1 {
		t.Fatalf("purge: %d %v", removed, err)
	}
	status, body := f.do("GET", "/v1/tenants/ten_acme/roles/"+role["id"].(string), f.admin, nil)
	f.wantStatus(status, body, http.StatusOK)
	if !slices.Equal(strs(body["permissions"]), []string{"deals:read"}) || body["assignments"].(float64) != 1 {
		t.Errorf("role after purge: %v", body)
	}
	if got := f.grants("deals", "ana"); !slices.Equal(got, []string{"deals:read@" + assignment}) {
		t.Errorf("grants after purge: %v", got)
	}
	if f.auditCount("role.purge_module", "success") != 1 || f.auditCount("permissions.purge", "success") != 1 {
		t.Error("purge wasn't audited")
	}
}

func TestTemplateUpdateNeverChangesARole(t *testing.T) {
	f := newRolesFixture(t)
	role := f.createRole(map[string]any{"template": map[string]string{"module": "deals", "id": "rep"}})
	f.deploy(testCatalog(t, 2))
	status, body := f.do("GET", "/v1/tenants/ten_acme/roles/"+role["id"].(string), f.admin, nil)
	f.wantStatus(status, body, http.StatusOK)
	template := body["template"].(map[string]any)
	if !slices.Equal(strs(body["permissions"]), []string{"deals:read", "deals:write"}) ||
		template["version"].(float64) != 1 || template["latest_version"].(float64) != 2 {
		t.Errorf("role after template update: %v", body)
	}
}

func TestRetiredPermissionConfersNothing(t *testing.T) {
	f := newRolesFixture(t)
	f.assign("ana", f.createRole(map[string]any{"name": "Rep", "permissions": []string{"deals:read", "deals:write"}}))
	f.deploy(catalogOf(t, dealsModule(2, roles.LifecycleRetired), crmModule()))
	got := f.grants("deals", "ana")
	if len(got) != 1 || slices.ContainsFunc(got, func(g string) bool { return g[:11] == "deals:write" }) {
		t.Errorf("grants with deals:write retired: %v", got)
	}
}

func TestAModuleReadsOnlyItsOwnRoles(t *testing.T) {
	f := newRolesFixture(t)
	own := f.createRole(map[string]any{"name": "Rep", "permissions": []string{"deals:read"}})
	mixed := f.createRole(map[string]any{"name": "Mixed", "permissions": []string{"deals:read", "crm:read"}})
	other := f.createRole(map[string]any{"name": "CRM only", "permissions": []string{"crm:read"}})
	assignment := f.assign("ana", own)
	f.assign("ben", mixed)
	f.assign("ben", other)
	q := "/v1/module-roles?tenant=ten_acme&module=deals"
	status, body := f.do("GET", q, f.serviceToken(otherService), nil)
	f.wantStatus(status, body, http.StatusOK)
	roles := body["roles"].([]any)
	if len(roles) != 2 {
		t.Fatalf("another module's role was listed: %v", roles)
	}
	for _, raw := range roles {
		for _, key := range raw.(map[string]any)["permissions"].([]any) {
			if !strings.HasPrefix(key.(string), "deals:") {
				t.Errorf("another module's permission was listed: %v", raw)
			}
		}
	}
	found := map[string]string{}
	for _, raw := range body["assignments"].([]any) {
		a := raw.(map[string]any)
		found[a["id"].(string)] = a["user_id"].(string)
		if a["role_id"] == other["id"] {
			t.Errorf("an assignment of another module's role was listed: %v", a)
		}
	}
	if found[assignment] != f.users["ana"] || len(found) != 2 {
		t.Errorf("assignments: %v", found)
	}
	status, body = f.do("GET", q, f.serviceToken(listedService), nil)
	f.wantStatus(status, body, http.StatusForbidden)
	if status, _ := f.do("GET", q, f.login("ana", "ten_acme"), nil); status != http.StatusUnauthorized {
		t.Errorf("a person's token: %d", status)
	}
	status, body = f.do("GET", "/v1/module-roles?tenant=ten_acme", f.serviceToken(otherService), nil)
	f.wantStatus(status, body, http.StatusBadRequest)
}
