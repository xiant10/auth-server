package server

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"t10-auth-server/internal/directory"
)

// The harness's console and workbench, which /admin and the account page name.
const (
	testConsoleURL   = "http://console.test"
	testWorkbenchURL = "http://workbench.test"
)

func TestSafeNextAllowsOnlyAdminItself(t *testing.T) {
	tests := map[string]string{
		"/admin":                     "/admin",
		"/admin/tenants/ten_acme":    defaultNext,
		"/administrator":             defaultNext,
		"//evil.example/admin":       defaultNext,
		"https://evil.example/admin": defaultNext,
	}
	for input, want := range tests {
		if got := safeNext(input); got != want {
			t.Errorf("safeNext(%q) = %q", input, got)
		}
	}
}

// adminFixture has ten_acme with one admin and one member, and an unrelated
// ten_other with its own admin.
func adminFixture(t *testing.T, dev bool) (*harness, string) {
	t.Helper()
	h := newHarness(t, dev)
	h.tenant("ten_acme")
	h.tenant("ten_other")
	h.user("boss", map[string]string{"ten_acme": directory.RoleAdmin})
	member := h.user("grace", map[string]string{"ten_acme": directory.RoleMember})
	h.user("rival", map[string]string{"ten_other": directory.RoleAdmin})
	return h, member
}

func (h *harness) signedIn(name string) *browser {
	h.t.Helper()
	b := h.browser()
	if status := b.signIn(name, testPassword, ""); status != http.StatusSeeOther {
		h.t.Fatalf("sign in %s: %d", name, status)
	}
	return b
}

func wantPage(t *testing.T, got int, body string, want int, contains ...string) {
	t.Helper()
	if got != want {
		t.Fatalf("status = %d, want %d: %s", got, want, body)
	}
	for _, s := range contains {
		if !strings.Contains(body, s) {
			t.Errorf("page lacks %q", s)
		}
	}
}

func TestAdminPointsEachRoleToItsHome(t *testing.T) {
	h, _ := adminFixture(t, false)
	status, location, _ := h.browser().get("/admin/tenants/ten_acme")
	if status != http.StatusSeeOther || !strings.Contains(location, "/v1/signin?next=%2Fadmin%2Ftenants%2Ften_acme") {
		t.Errorf("anonymous: %d %s", status, location)
	}
	for path, want := range map[string]string{"/admin": testWorkbenchURL + "/admin", "/admin/tenants/ten_acme": testWorkbenchURL + "/admin"} {
		if status, location, _ := h.signedIn("boss").get(path); status != http.StatusSeeOther || location != want {
			t.Errorf("tenant admin %s: %d %s", path, status, location)
		}
	}
	if status, location, _ := h.signedIn("grace").get("/admin"); status != http.StatusSeeOther || location != "/" {
		t.Errorf("member: %d %s", status, location)
	}

	// The platform role is enough to be pointed at the console, which asks for
	// a factor itself.
	root := h.user("root", nil)
	h.platformAdmin(root)
	if status, location, _ := h.signedIn("root").get("/admin"); status != http.StatusSeeOther || location != testConsoleURL {
		t.Errorf("platform admin: %d %s", status, location)
	}
	if _, err := h.dir.Add(context.Background(), "test", "ten_acme", root, directory.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	status, _, body := h.signedIn("root").get("/admin")
	wantPage(t, status, body, http.StatusOK, `href="`+testConsoleURL+`"`, `href="`+testWorkbenchURL+`/admin"`)
}

func TestAccountPageHasAWayBack(t *testing.T) {
	h, _ := adminFixture(t, false)
	for _, name := range []string{"boss", "grace"} {
		if _, _, body := h.signedIn(name).get("/v1/account"); !strings.Contains(body, `href="`+testWorkbenchURL+`/t/ten_acme/"`) || strings.Contains(body, testConsoleURL) {
			t.Errorf("%s's links are wrong: %s", name, body)
		}
	}
}

func TestFrontDoorSendsEachPersonWhereTheyBelong(t *testing.T) {
	h, _ := adminFixture(t, false)
	if status, location, _ := h.browser().get("/"); status != http.StatusSeeOther || !strings.Contains(location, "/v1/signin?next=%2F") {
		t.Errorf("anonymous: %d %s", status, location)
	}
	if status, location, _ := h.signedIn("grace").get("/"); status != http.StatusSeeOther || location != testWorkbenchURL+"/t/ten_acme/" {
		t.Errorf("one tenant: %d %s", status, location)
	}
	root := h.user("root", nil)
	h.platformAdmin(root)
	if status, location, _ := h.signedIn("root").get("/"); status != http.StatusSeeOther || location != testConsoleURL {
		t.Errorf("platform only: %d %s", status, location)
	}
	h.user("alone", nil)
	status, location, body := h.signedIn("alone").get("/")
	wantPage(t, status, body, http.StatusOK, "not in a tenant yet", "invitation link", `href="/v1/account"`, `action="/v1/signout"`)
	if location != "" {
		t.Errorf("no places: %s", location)
	}
	h.user("several", map[string]string{"ten_acme": directory.RoleMember, "ten_other": directory.RoleAdmin})
	status, _, body = h.signedIn("several").get("/")
	wantPage(t, status, body, http.StatusOK, "Where to?", testWorkbenchURL+"/t/ten_acme/", testWorkbenchURL+"/t/ten_other/")
	if strings.Contains(body, testConsoleURL) {
		t.Errorf("console offered to a non-admin: %s", body)
	}
	if _, err := h.dir.Add(context.Background(), "test", "ten_acme", root, directory.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	status, _, body = h.signedIn("root").get("/")
	wantPage(t, status, body, http.StatusOK, "Where to?", testWorkbenchURL+"/t/ten_acme/", `href="`+testConsoleURL+`"`, "internal network")
}

func TestHomesListOnlyThePersonsOwnPlaces(t *testing.T) {
	h, _ := adminFixture(t, false)
	grace, _ := h.redeem(h.signedIn("grace"))
	status, body := h.do("GET", "/v1/me/homes", grace, nil)
	h.wantStatus(status, body, http.StatusOK)
	tenants := body["workbench"].(map[string]any)["tenants"].([]any)
	row := tenants[0].(map[string]any)
	if len(tenants) != 1 || row["id"] != "ten_acme" || row["url"] != testWorkbenchURL+"/t/ten_acme/" || body["console"] != nil {
		t.Errorf("member: %v", body)
	}
	if !strings.HasSuffix(body["account"].(map[string]any)["url"].(string), "/v1/account") {
		t.Errorf("account: %v", body)
	}
	root := h.user("root", nil)
	h.platformAdmin(root)
	token, _ := h.redeem(h.signedIn("root"))
	status, body = h.do("GET", "/v1/me/homes", token, nil)
	h.wantStatus(status, body, http.StatusOK)
	if body["workbench"] != nil || body["console"].(map[string]any)["url"] != testConsoleURL {
		t.Errorf("platform admin: %v", body)
	}
	if status, _ := h.do("GET", "/v1/me/homes", "", nil); status != http.StatusUnauthorized {
		t.Errorf("no token: %d", status)
	}
}

func TestAnInvitationLandsInItsTenant(t *testing.T) {
	h, _ := adminFixture(t, false)
	boss, _ := h.redeem(h.signedIn("boss"))
	status, invited := h.do("POST", "/v1/tenants/ten_acme/invitations", boss, map[string]string{"role": "member"})
	h.wantStatus(status, invited, http.StatusCreated)
	joinURL, _ := url.Parse(invited["join_url"].(string))
	h.user("newcomer", nil)
	status, location, body := h.signedIn("newcomer").post("/v1/join", url.Values{"invite": {joinURL.Query().Get("invite")}})
	if status != http.StatusSeeOther || location != testWorkbenchURL+"/t/ten_acme/" {
		t.Errorf("join: %d %s %s", status, location, body)
	}
}

func TestTenantAdminStopsAgentsAndReadsActivityOverJSON(t *testing.T) {
	h, _ := adminFixture(t, true)
	const base = "/v1/tenants/ten_acme"
	id := h.grant(piRuntime, h.login("grace", ""), []string{"crm:read"}, []string{piRuntime})
	child := h.grant(piRuntime, h.mint(piRuntime, id), []string{"crm:read"}, []string{piRuntime})
	boss := h.login("boss", "ten_acme")

	status, body := h.do("GET", base+"/grants", boss, nil)
	h.wantStatus(status, body, http.StatusOK)
	grants := body["grants"].([]any)
	if len(grants) != 2 || grants[0].(map[string]any)["who"] != "grace" || grants[0].(map[string]any)["running"] != true {
		t.Fatalf("grants: %v", grants)
	}

	rival := h.login("rival", "ten_other")
	for path, want := range map[string]int{
		base + "/grants":                                 http.StatusForbidden,
		base + "/grants/" + id + "/revoke":               http.StatusForbidden,
		"/v1/tenants/ten_other/grants/" + id + "/revoke": http.StatusNotFound,
	} {
		method := "POST"
		if strings.HasSuffix(path, "/grants") {
			method = "GET"
		}
		if status, body := h.do(method, path, rival, nil); status != want {
			t.Errorf("another tenant's admin, %s: %d %v", path, status, body)
		}
	}
	if status, _ := h.do("POST", base+"/grants/"+id+"/revoke", h.login("grace", "ten_acme"), nil); status != http.StatusForbidden {
		t.Errorf("a plain member: %d", status)
	}

	status, body = h.do("POST", base+"/grants/"+id+"/revoke", boss, nil)
	h.wantStatus(status, body, http.StatusOK)
	h.wantStopped(piRuntime, child)
	_, body = h.do("GET", base+"/grants", boss, nil)
	for _, g := range body["grants"].([]any) {
		if g.(map[string]any)["running"] == true {
			t.Errorf("a stopped chain still runs: %v", g)
		}
	}

	status, body = h.do("GET", base+"/audit", boss, nil)
	h.wantStatus(status, body, http.StatusOK)
	if !slices.ContainsFunc(body["records"].([]any), func(r any) bool { return r.(map[string]any)["action"] == "grant.revoke" }) {
		t.Fatalf("activity has no revoke: %v", body["records"])
	}
	if status, _ := h.do("GET", base+"/audit", rival, nil); status != http.StatusForbidden {
		t.Errorf("another tenant reads activity: %d", status)
	}
}

func TestTenantMembersCarryNamesAndPlacement(t *testing.T) {
	h, member := adminFixture(t, true)
	boss := h.login("boss", "ten_acme")
	unit := h.unit("Sales", "")
	h.mustPlace(member, h.userID("boss"), unit)
	status, body := h.do("GET", "/v1/tenants/ten_acme/members", boss, nil)
	h.wantStatus(status, body, http.StatusOK)
	for _, m := range body["members"].([]any) {
		row := m.(map[string]any)
		if row["user_id"] == member && (row["name"] != "grace" || row["manager_name"] != "boss" || row["org_unit_name"] != "Sales" || row["user_status"] != "active") {
			t.Errorf("member row: %v", row)
		}
	}
}

func TestRequiringAFactorNeedsOneYourself(t *testing.T) {
	h, _ := adminFixture(t, true)
	boss := h.login("boss", "ten_acme")
	status, body := h.do("PATCH", "/v1/tenants/ten_acme", boss, map[string]bool{"require_mfa": true})
	h.wantStatus(status, body, http.StatusConflict)
	if tenant, err := h.dir.GetTenant(context.Background(), "ten_acme"); err != nil || tenant.RequireMFA {
		t.Errorf("the setting changed: %+v %v", tenant, err)
	}
	status, body = h.do("PATCH", "/v1/tenants/ten_acme", boss, map[string]bool{"require_mfa": false})
	h.wantStatus(status, body, http.StatusOK)
}

func TestPlatformAuditIsForPlatformAdmins(t *testing.T) {
	h, _, _, rootToken := platformFixture(t)
	status, body := h.do("POST", "/v1/identifiers/release", rootToken, map[string]string{"name": "grace"})
	h.wantStatus(status, body, http.StatusOK)
	status, body = h.do("GET", "/v1/audit", rootToken, nil)
	h.wantStatus(status, body, http.StatusOK)
	if records := body["records"].([]any); len(records) == 0 || records[0].(map[string]any)["action"] != "name.release" {
		t.Fatalf("audit: %v", records)
	}
	if status, _ := h.do("GET", "/v1/audit", h.login("boss", "ten_acme"), nil); status != http.StatusForbidden {
		t.Errorf("tenant admin reads platform audit: %d", status)
	}
}

func TestTenantSeesPlatformAdminsStepIn(t *testing.T) {
	h, _, root, rootToken := platformFixture(t)
	boss := h.login("boss", "ten_acme")
	const base = "/v1/tenants/ten_acme"
	uses := func() (reads, writes int) {
		t.Helper()
		status, body := h.do("GET", base+"/audit", boss, nil)
		h.wantStatus(status, body, http.StatusOK)
		for _, record := range body["records"].([]any) {
			row := record.(map[string]any)
			switch row["action"] {
			case "platform_access.read":
				reads++
			case "platform_access.write":
				writes++
			default:
				continue
			}
			if row["actor"] != "user:"+root {
				t.Errorf("actor: %v", row)
			}
		}
		return reads, writes
	}

	// The tenant's own admin leaves no such row.
	status, body := h.do("GET", base+"/members", boss, nil)
	h.wantStatus(status, body, http.StatusOK)
	if reads, writes := uses(); reads != 0 || writes != 0 {
		t.Fatalf("own admin recorded: %d reads, %d writes", reads, writes)
	}

	// A token with no tenant still reaches the routes, and reads collapse to one row.
	for _, path := range []string{base + "/members", base + "/units"} {
		status, body = h.do("GET", path, rootToken, nil)
		h.wantStatus(status, body, http.StatusOK)
	}
	if reads, writes := uses(); reads != 1 || writes != 0 {
		t.Errorf("after reads: %d reads, %d writes", reads, writes)
	}

	// Every write has its own row.
	for range 2 {
		status, body = h.do("PATCH", base, rootToken, map[string]bool{"require_mfa": false})
		h.wantStatus(status, body, http.StatusOK)
	}
	if reads, writes := uses(); reads != 1 || writes != 2 {
		t.Errorf("after writes: %d reads, %d writes", reads, writes)
	}

	// Someone with both roles, working in their own tenant, isn't stepping in.
	h.platformAdmin(h.userID("boss"))
	status, body = h.do("GET", base+"/members", h.login("boss", "ten_acme"), nil)
	h.wantStatus(status, body, http.StatusOK)
	if reads, writes := uses(); reads != 1 || writes != 2 {
		t.Errorf("both roles recorded: %d reads, %d writes", reads, writes)
	}
}

func TestRuntimesAreForPlatformAdmins(t *testing.T) {
	h, _, _, rootToken := platformFixture(t)
	status, body := h.do("GET", "/v1/runtimes", rootToken, nil)
	h.wantStatus(status, body, http.StatusOK)
	runtimes := body["runtimes"].([]any)
	if len(runtimes) == 0 || runtimes[0].(map[string]any)["audiences"] == nil {
		t.Fatalf("runtimes: %v", body)
	}
	if status, _ := h.do("GET", "/v1/runtimes", h.login("boss", "ten_acme"), nil); status != http.StatusForbidden {
		t.Errorf("tenant admin reads runtimes: %d", status)
	}
}

func TestTOTPPageShowsAQRCode(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.signedIn("grace")
	status, _, body := b.post("/v1/account", url.Values{"action": {"totp_start"}, "password": {testPassword}})
	wantPage(t, status, body, http.StatusOK, `src="data:image/png;base64,`)
}

func TestMeAccess(t *testing.T) {
	h, member := adminFixture(t, false)
	root := h.user("root", nil)
	h.platformAdmin(root)
	boss := h.signedIn("boss")
	bossToken, _ := h.redeem(boss)

	status, body := h.do("GET", "/v1/me/access", bossToken, nil)
	h.wantStatus(status, body, http.StatusOK)
	if body["active_tenant"] != "ten_acme" || body["tenant_admin"] != true || body["platform_admin"] != false || body["platform_verified"] != false {
		t.Fatalf("tenant admin: %v", body)
	}
	// A tenant admin with no recent factor isn't verified for policy changes.
	if body["tenant_verified"] != false {
		t.Fatalf("tenant admin without a factor: %v", body)
	}

	grace := h.signedIn("grace")
	graceToken, _ := h.redeem(grace)
	status, body = h.do("GET", "/v1/me/access", graceToken, nil)
	h.wantStatus(status, body, http.StatusOK)
	if body["user_id"] != member || body["tenant_admin"] != false || body["tenant_verified"] != false {
		t.Fatalf("member: %v", body)
	}

	// The role alone isn't verified: a platform admin needs a recent factor.
	b := h.signedIn("root")
	access, _ := h.redeem(b)
	status, body = h.do("GET", "/v1/me/access", access, nil)
	h.wantStatus(status, body, http.StatusOK)
	if body["platform_admin"] != true || body["mfa"] != false || body["platform_verified"] != false || body["active_tenant"] != "" {
		t.Fatalf("no factor: %v", body)
	}

	secret := b.enrollTOTP()
	fresh := h.browser()
	if st := fresh.signIn("root", testPassword, totpAt(t, secret, 1)); st != http.StatusSeeOther {
		t.Fatalf("sign in: %d", st)
	}
	access, _ = h.redeem(fresh)
	status, body = h.do("GET", "/v1/me/access", access, nil)
	h.wantStatus(status, body, http.StatusOK)
	if body["mfa"] != true || body["platform_verified"] != true {
		t.Fatalf("fresh factor: %v", body)
	}

	if _, err := h.pool.Exec(context.Background(), "UPDATE auth.sessions SET mfa_at = now() - interval '16 minutes'"); err != nil {
		t.Fatal(err)
	}
	status, body = h.do("GET", "/v1/me/access", access, nil)
	h.wantStatus(status, body, http.StatusOK)
	if body["mfa"] != true || body["platform_verified"] != false {
		t.Fatalf("stale factor: %v", body)
	}

	if status, _ := h.do("GET", "/v1/me/access", "", nil); status != http.StatusUnauthorized {
		t.Fatalf("no token: %d", status)
	}
}

func TestMeAccessDevModeWaivesTheFactor(t *testing.T) {
	h := newHarness(t, true)
	h.platformAdmin(h.user("root", nil))
	access, _ := h.redeem(h.signedIn("root"))
	status, body := h.do("GET", "/v1/me/access", access, nil)
	h.wantStatus(status, body, http.StatusOK)
	if body["mfa"] != false || body["platform_verified"] != true {
		t.Fatalf("dev mode: %v", body)
	}
}

func TestMeAccessDevModeWaivesTheTenantFactor(t *testing.T) {
	h, _ := adminFixture(t, true)
	bossToken, _ := h.redeem(h.signedIn("boss"))
	status, body := h.do("GET", "/v1/me/access", bossToken, nil)
	h.wantStatus(status, body, http.StatusOK)
	if body["tenant_admin"] != true || body["tenant_verified"] != true {
		t.Fatalf("dev mode tenant admin: %v", body)
	}
}

func TestListTenantsIsForVerifiedPlatformAdmins(t *testing.T) {
	h, _ := adminFixture(t, true)
	h.platformAdmin(h.user("root", nil))
	bossToken, _ := h.redeem(h.signedIn("boss"))
	if status, _ := h.do("GET", "/v1/tenants", bossToken, nil); status != http.StatusForbidden {
		t.Fatalf("tenant admin: %d", status)
	}
	access, _ := h.redeem(h.signedIn("root"))
	status, body := h.do("GET", "/v1/tenants?q=acme", access, nil)
	h.wantStatus(status, body, http.StatusOK)
	rows := body["tenants"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["id"] != "ten_acme" {
		t.Fatalf("tenants: %v", rows)
	}
}

// TestStepUpForAnOutsideClient walks what t10-console does before a change,
// against this server outside dev mode, so the console's half of the step-up has
// something real to rest on.
func TestStepUpForAnOutsideClient(t *testing.T) {
	h := newHarness(t, false)
	h.platformAdmin(h.user("root", nil))
	first := h.signedIn("root")
	secret := first.enrollTOTP()

	b := h.browser()
	if st := b.signIn("root", testPassword, totpAt(t, secret, 1)); st != http.StatusSeeOther {
		t.Fatalf("sign in: %d", st)
	}
	access, refreshToken := h.redeem(b)
	// Sixteen minutes pass, so the factor ages and a code can be used again.
	for _, sql := range []string{
		"UPDATE auth.sessions SET mfa_at = now() - interval '16 minutes'",
		"UPDATE auth.mfa_factors SET last_used_step = 0",
	} {
		if _, err := h.pool.Exec(context.Background(), sql); err != nil {
			t.Fatal(err)
		}
	}

	verified := func(token string) bool {
		t.Helper()
		status, body := h.do("GET", "/v1/me/access", token, nil)
		h.wantStatus(status, body, http.StatusOK)
		return body["platform_verified"] == true
	}
	if verified(access) {
		t.Fatal("a stale factor is verified")
	}
	// A refresh doesn't renew the factor, which is why a step-up needs a new code.
	refreshed := h.refreshOK(refreshToken)
	status, body := h.token(refresh(refreshed))
	h.wantStatus(status, body, http.StatusOK)
	if verified(body["access_token"].(string)) {
		t.Fatal("a refresh renewed the factor")
	}

	next := authorizePath("stepup")
	status, _, page := b.get("/v1/signin?reason=stepup&next=" + url.QueryEscape(next))
	wantPage(t, status, page, http.StatusOK, "Sign in again")
	status, location, page := b.post("/v1/signin", url.Values{
		"name": {"root"}, "password": {testPassword}, "code": {totpAt(t, secret, 0)}, "next": {next},
	})
	if status != http.StatusSeeOther || !strings.HasPrefix(location, "/v1/authorize?") {
		t.Fatalf("step-up sign-in: %d %s %s", status, location, page)
	}
	fresh, _ := h.redeem(b)
	if !verified(fresh) {
		t.Fatal("a stepped-up session isn't verified")
	}
	if verified(access) {
		t.Fatal("the old session gained a fresh factor")
	}
}
