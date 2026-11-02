package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"t10-auth-server/internal/directory"
)

func TestAdminRoutesAreNeverPublic(t *testing.T) {
	for _, rt := range New(Deps{}).routes() {
		if !strings.HasPrefix(rt.pattern, "/admin") {
			continue
		}
		switch rt.access {
		case accessAdmin, accessAdminTenant, accessAdminPlatform:
		default:
			t.Errorf("%s %s has access %d", rt.method, rt.pattern, rt.access)
		}
	}
}

func TestSafeNextAllowsOnlyCleanAdminPaths(t *testing.T) {
	tests := map[string]string{
		"/admin":                     "/admin",
		"/admin/tenants/ten_acme":    "/admin/tenants/ten_acme",
		"/admin/tenants?q=a":         "/admin/tenants?q=a",
		"/admin/../v1/token":         defaultNext,
		"/admin//evil.example":       defaultNext,
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

func TestAdminNeedsSignIn(t *testing.T) {
	h, _ := adminFixture(t, false)
	status, location, _ := h.browser().get("/admin/tenants/ten_acme")
	if status != http.StatusSeeOther || !strings.Contains(location, "/v1/signin?next=%2Fadmin%2Ftenants%2Ften_acme") {
		t.Errorf("anonymous: %d %s", status, location)
	}
}

func TestTenantAdminPageShowsItsScope(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.signedIn("boss")
	status, location, _ := b.get("/admin")
	if status != http.StatusSeeOther || location != "/admin/tenants/ten_acme" {
		t.Fatalf("home: %d %s", status, location)
	}
	status, _, body := b.get("/admin/tenants/ten_acme")
	wantPage(t, status, body, http.StatusOK, "Tenant: ten_acme", "scope-tenant", "grace", `action="/v1/signout"`)
	for _, tab := range []string{"", "?tab=invite", "?tab=security", "?tab=activity"} {
		status, _, body := b.get("/admin/tenants/ten_acme" + tab)
		wantPage(t, status, body, http.StatusOK, "Tenant: ten_acme", `aria-current="page"`)
		for _, platformOnly := range []string{"Platform action", "/suspend", `href="/admin/tenants"`} {
			if strings.Contains(body, platformOnly) {
				t.Errorf("tenant admin sees %q on %q", platformOnly, tab)
			}
		}
	}
}

func TestSignOutFromAdmin(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.signedIn("boss")
	status, location, _ := b.post("/v1/signout", url.Values{})
	if status != http.StatusSeeOther {
		t.Fatalf("sign out: %d", status)
	}
	status, _, body := b.get(location)
	wantPage(t, status, body, http.StatusOK, "You&#39;re signed out")
	if status, _, _ := b.get("/admin/tenants/ten_acme"); status != http.StatusSeeOther {
		t.Errorf("admin page after sign-out: %d", status)
	}
}

func TestRefusedUserCanSignOut(t *testing.T) {
	h, _ := adminFixture(t, false)
	status, _, body := h.signedIn("grace").get("/admin")
	wantPage(t, status, body, http.StatusForbidden, `action="/v1/signout"`)
}

func TestCopyScriptOnlyWhereThereIsALink(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.signedIn("boss")
	if _, _, body := b.get("/admin/tenants/ten_acme"); strings.Contains(body, "<script") {
		t.Error("tenant page has a script")
	}
	resp, err := b.client.Do(func() *http.Request {
		req, _ := http.NewRequest("POST", h.url+"/admin/tenants/ten_acme/invitations", strings.NewReader("role=member"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", h.url)
		return req
	}())
	if err != nil {
		t.Fatal(err)
	}
	policy := resp.Header.Get("Content-Security-Policy")
	_, _, body := readPage(t, resp)
	if !strings.Contains(policy, "script-src 'nonce-") || !strings.Contains(body, "<script nonce=") {
		t.Errorf("no nonce script: %s", policy)
	}
	if strings.Contains(policy, "unsafe-inline'; script") || strings.Contains(policy, "script-src 'unsafe") {
		t.Errorf("policy allows inline script: %s", policy)
	}
}

func TestTenantTabIgnoresUnknownValues(t *testing.T) {
	h, _ := adminFixture(t, false)
	status, _, body := h.signedIn("boss").get(`/admin/tenants/ten_acme?tab="><script>`)
	wantPage(t, status, body, http.StatusOK, "grace")
	if strings.Contains(body, "<script>") {
		t.Error("tab value reached the page")
	}
}

func TestAdminRefusesEveryoneElse(t *testing.T) {
	h, _ := adminFixture(t, false)
	for name, path := range map[string]string{
		"grace": "/admin/tenants/ten_acme",
		"rival": "/admin/tenants/ten_acme",
		"boss":  "/admin/tenants",
	} {
		status, _, body := h.signedIn(name).get(path)
		wantPage(t, status, body, http.StatusForbidden, "No access")
	}
	status, _, body := h.signedIn("grace").get("/admin")
	wantPage(t, status, body, http.StatusForbidden)

	var denied int
	err := h.pool.QueryRow(context.Background(),
		"SELECT count(*) FROM auth.audit_log WHERE outcome = 'denied' AND action LIKE 'http.%'").Scan(&denied)
	if err != nil {
		t.Fatal(err)
	}
	if denied != 3 {
		t.Errorf("%d denials audited, want 3", denied)
	}
}

func TestAdminWritesAreRefusedLikeReads(t *testing.T) {
	h, member := adminFixture(t, false)
	rival := h.signedIn("rival")
	for path, form := range map[string]url.Values{
		"/admin/tenants/ten_acme/settings":                          {"require_mfa": {"on"}},
		"/admin/tenants/ten_acme/invitations":                       {"role": {"admin"}},
		"/admin/tenants/ten_acme/members/" + member:                 {"role": {"admin"}, "status": {"active"}},
		"/admin/tenants/ten_acme/members/" + member + "/reset-link": {},
		"/admin/tenants/ten_acme/suspend":                           {},
		"/admin/tenants/ten_acme/members":                           {"user_id": {member}, "role": {"admin"}},
		"/admin/tenants":                                            {"name": {"Evil"}},
		"/admin/names/release":                                      {"name": {"grace"}},
	} {
		if status, _, body := rival.post(path, form); status != http.StatusForbidden {
			t.Errorf("%s: %d %s", path, status, body)
		}
	}
	boss := h.signedIn("boss")
	if status, _, _ := boss.post("/admin/tenants/ten_acme/suspend", url.Values{}); status != http.StatusForbidden {
		t.Errorf("tenant admin suspended a tenant: %d", status)
	}
}

func TestAdminPostNeedsSameOrigin(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.signedIn("boss")
	req, err := http.NewRequest("POST", h.url+"/admin/tenants/ten_acme/invitations", strings.NewReader("role=admin"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if status, _, body := readPage(t, resp); status != http.StatusForbidden {
		t.Errorf("cross-origin post: %d %s", status, body)
	}
}

func TestTenantAdminWork(t *testing.T) {
	h, member := adminFixture(t, false)
	b := h.signedIn("boss")
	const page = "/admin/tenants/ten_acme"

	status, _, body := b.post(page+"/invitations", url.Values{"role": {"member"}})
	wantPage(t, status, body, http.StatusOK, "/v1/register?invite=", "/v1/join?invite=", "won&#39;t be shown again")

	status, _, body = b.post(page+"/members/"+member, url.Values{"role": {"admin"}, "status": {"active"}})
	wantPage(t, status, body, http.StatusOK, "Member updated")
	status, _, body = b.post(page+"/members/"+member, url.Values{"role": {"member"}, "status": {"active"}})
	wantPage(t, status, body, http.StatusOK)

	status, _, body = b.post(page+"/members/"+member+"/reset-link", url.Values{"name": {"grace"}})
	wantPage(t, status, body, http.StatusOK, "/v1/reset?token=", "for grace", "data-copy")
	status, _, body = b.get(page + "?tab=activity")
	wantPage(t, status, body, http.StatusOK, "membership.update", "password.reset_issue", "invitation.create")

	status, _, body = b.post(page+"/members/"+member, url.Values{"role": {"owner"}, "status": {"active"}})
	wantPage(t, status, body, http.StatusBadRequest, "isn&#39;t valid")

	status, _, body = b.post(page+"/settings", url.Values{"require_mfa": {"on"}})
	wantPage(t, status, body, http.StatusBadRequest, "lock you out")
	if tenant, err := h.dir.GetTenant(context.Background(), "ten_acme"); err != nil || tenant.RequireMFA {
		t.Errorf("policy changed: %+v %v", tenant, err)
	}
}

func TestAdminResetFollowsTheSameRuleAsTheAPI(t *testing.T) {
	h, _ := adminFixture(t, false)
	both := h.user("both", map[string]string{"ten_acme": directory.RoleMember, "ten_other": directory.RoleMember})
	b := h.signedIn("boss")
	status, _, body := b.post("/admin/tenants/ten_acme/members/"+both+"/reset-link", url.Values{})
	wantPage(t, status, body, http.StatusForbidden, "Only a platform admin")
	if strings.Contains(body, "/v1/reset?token=") {
		t.Error("issued a link anyway")
	}
}

func TestLastAdminCannotBeRemoved(t *testing.T) {
	h, _ := adminFixture(t, false)
	var boss string
	if err := h.pool.QueryRow(context.Background(),
		"SELECT user_id FROM auth.user_identifiers WHERE value = 'boss'").Scan(&boss); err != nil {
		t.Fatal(err)
	}
	b := h.signedIn("boss")
	path := "/admin/tenants/ten_acme/members/" + boss
	for _, form := range []url.Values{
		{"role": {"member"}, "status": {"active"}},
		{"role": {"admin"}, "status": {"inactive"}},
	} {
		status, _, body := b.post(path, form)
		wantPage(t, status, body, http.StatusConflict, "at least one active admin")
	}
	access, _ := h.redeem(b)
	role := "member"
	status, body := h.do("PATCH", "/v1/tenants/ten_acme/members/"+boss, access, map[string]*string{"role": &role})
	h.wantStatus(status, body, http.StatusConflict)
}

func TestMFATenantRefusesAdminCookieWithoutAFactor(t *testing.T) {
	h, _ := adminFixture(t, false)
	if err := h.dir.SetRequireMFA(context.Background(), "test", "ten_acme", true); err != nil {
		t.Fatal(err)
	}
	status, _, body := h.signedIn("boss").get("/admin/tenants/ten_acme")
	wantPage(t, status, body, http.StatusForbidden, "requires a second factor")
}

func TestPlatformAdminStepsUpWhenTheFactorIsStale(t *testing.T) {
	h, _ := adminFixture(t, false)
	root := h.user("root", nil)
	h.platformAdmin(root)

	noFactor := h.signedIn("root")
	status, _, body := noFactor.get("/admin/tenants")
	wantPage(t, status, body, http.StatusForbidden, "need an authenticator")

	secret := noFactor.enrollTOTP()
	b := h.browser()
	if status := b.signIn("root", testPassword, totpAt(t, secret, 1)); status != http.StatusSeeOther {
		t.Fatalf("sign in: %d", status)
	}
	status, _, body = b.get("/admin/tenants/ten_acme?tab=security")
	wantPage(t, status, body, http.StatusOK, "Platform action", "/suspend", "Tenant: ten_acme", `href="/admin/tenants" aria-current="page"`)
	status, _, body = b.get("/admin/tenants")
	wantPage(t, status, body, http.StatusOK, "scope-platform", "Platform-wide", "ten_other")
	status, _, body = b.get("/admin/tenants?q=OTHER")
	wantPage(t, status, body, http.StatusOK, "ten_other")
	if strings.Contains(body, `href="/admin/tenants/ten_acme"`) {
		t.Error("search kept a tenant it should drop")
	}

	status, _, body = b.post("/admin/tenants/ten_acme/suspend", url.Values{})
	wantPage(t, status, body, http.StatusOK, "Tenant suspended", "Reactivate")
	status, _, body = b.post("/admin/tenants/ten_acme/activate", url.Values{})
	wantPage(t, status, body, http.StatusOK, "Tenant active")
	status, location, _ := b.post("/admin/tenants", url.Values{"name": {"New"}, "id": {"ten_new"}})
	if status != http.StatusSeeOther || location != "/admin/tenants/ten_new" {
		t.Errorf("create: %d %s", status, location)
	}
	status, _, body = b.post("/admin/tenants", url.Values{"name": {"Dup"}, "id": {"ten_new"}})
	wantPage(t, status, body, http.StatusConflict, "already exists")
	status, _, body = b.post("/admin/tenants/ten_new/members", url.Values{"user_id": {root}, "role": {"admin"}})
	wantPage(t, status, body, http.StatusOK, "Member added")
	status, _, body = b.post("/admin/names/release", url.Values{"name": {"nobody"}})
	wantPage(t, status, body, http.StatusNotFound, "No account holds")
	status, _, body = b.get("/admin/names")
	wantPage(t, status, body, http.StatusOK, "scope-platform", "Release a name")
	status, _, body = b.post("/admin/names/release", url.Values{"name": {"grace"}})
	wantPage(t, status, body, http.StatusOK, "released")
	status, _, body = b.get("/admin/audit")
	wantPage(t, status, body, http.StatusOK, "name.release")

	if _, err := h.pool.Exec(context.Background(), "UPDATE auth.sessions SET mfa_at = now() - interval '16 minutes'"); err != nil {
		t.Fatal(err)
	}
	status, location, _ = b.get("/admin/tenants")
	if status != http.StatusSeeOther || !strings.Contains(location, "reason=stepup") || !strings.Contains(location, "next=%2Fadmin%2Ftenants") {
		t.Fatalf("stale get: %d %s", status, location)
	}
	status, _, body = b.get(location)
	wantPage(t, status, body, http.StatusOK, "Sign in again")
	status, location, _ = b.post("/admin/tenants/ten_acme/suspend", url.Values{})
	if status != http.StatusSeeOther || !strings.Contains(location, "next=%2Fadmin&") && !strings.HasSuffix(location, "next=%2Fadmin") {
		t.Fatalf("stale post: %d %s", status, location)
	}
	if tenant, err := h.dir.GetTenant(context.Background(), "ten_acme"); err != nil || tenant.Status != directory.TenantActive {
		t.Errorf("stale post changed the tenant: %+v %v", tenant, err)
	}
}

func TestAdminPagesEscapeInput(t *testing.T) {
	h, _ := adminFixture(t, false)
	const script = `<script>alert(1)</script>`
	if _, err := h.dir.Create(context.Background(), "test", "ten_xss", script); err != nil {
		t.Fatal(err)
	}
	h.user("xss", map[string]string{"ten_xss": directory.RoleAdmin})
	status, _, body := h.signedIn("xss").get("/admin/tenants/ten_xss")
	wantPage(t, status, body, http.StatusOK, "&lt;script&gt;")
	if strings.Contains(body, script) {
		t.Error("tenant name reached the page unescaped")
	}
}

func TestAccountPageLinksAdminsOnly(t *testing.T) {
	h, _ := adminFixture(t, false)
	if _, _, body := h.signedIn("boss").get("/v1/account"); !strings.Contains(body, `href="/admin"`) {
		t.Error("admin has no link")
	}
	if _, _, body := h.signedIn("grace").get("/v1/account"); strings.Contains(body, `href="/admin"`) {
		t.Error("member has a link")
	}
}

func TestTOTPPageShowsAQRCode(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.signedIn("grace")
	status, _, body := b.post("/v1/account", url.Values{"action": {"totp_start"}, "password": {testPassword}})
	wantPage(t, status, body, http.StatusOK, `src="data:image/png;base64,`)
}

func TestShortID(t *testing.T) {
	for input, want := range map[string]string{
		"user:usr_ced3251af88808d91916d236abd58542": "usr_ced3251a…",
		"authctl":                        "authctl",
		"ten_acme":                       "ten_acme",
		"ten_acme__voice-demo":           "ten_acme__vo…",
		"/v1/tenants/ten_long_name_here": "/v1/tenants/ten_long_name_here",
	} {
		if got := shortID(input); got != want {
			t.Errorf("shortID(%q) = %q", input, got)
		}
	}
}
