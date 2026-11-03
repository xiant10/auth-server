package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/samples"
)

func (h *harness) sampleBrowser(name string) *browser {
	h.t.Helper()
	b := h.browser()
	if status := b.signIn(name, samples.Password, ""); status != http.StatusSeeOther {
		h.t.Fatalf("sign in %s: %d", name, status)
	}
	return b
}

func (h *harness) sampleToken(name, tenant string) string {
	h.t.Helper()
	status, body := h.do("POST", "/v1/token", "", map[string]string{
		"grant_type": "password", "username": name, "password": samples.Password, "tenant": tenant,
	})
	if status != http.StatusOK {
		h.t.Fatalf("token for %s: %d %v", name, status, body)
	}
	return body["access_token"].(string)
}

func TestSampleAccountsGiveEachKindOfAccess(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	if err := samples.Add(ctx, h.pool, h.id, h.dir); err != nil {
		t.Fatal(err)
	}
	if err := samples.Add(ctx, h.pool, h.id, h.dir); !errors.Is(err, samples.ErrExists) {
		t.Errorf("second add: %v", err)
	}
	acme := "/v1/tenants/" + samples.TenantAcme + "/members"
	for name, want := range map[string]map[string]int{
		"sample-platform":     {acme: http.StatusOK, "/v1/tenants": http.StatusOK},
		"sample-acme-admin":   {acme: http.StatusOK, "/v1/tenants": http.StatusForbidden},
		"sample-globex-admin": {acme: http.StatusForbidden},
		"sample-member":       {acme: http.StatusForbidden},
	} {
		tenant := map[string]string{
			"sample-acme-admin": samples.TenantAcme, "sample-member": samples.TenantAcme, "sample-globex-admin": samples.TenantGlobex,
		}[name]
		token := h.sampleToken(name, tenant)
		for path, status := range want {
			if got, body := h.do("GET", path, token, nil); got != status {
				t.Errorf("%s %s = %d, want %d: %v", name, path, got, status, body)
			}
		}
	}
	// An inactive member gets no token for the tenant at all.
	if status, _ := h.do("POST", "/v1/token", "", map[string]string{
		"grant_type": "password", "username": "sample-inactive", "password": samples.Password, "tenant": samples.TenantAcme,
	}); status == http.StatusOK {
		t.Error("an inactive member got a tenant token")
	}
}

func TestSamplesRemoveLeavesNothingBehindAndNoOneElse(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	h.tenant("ten_real")
	real := h.user("real", map[string]string{"ten_real": directory.RoleMember})
	// A real account with a sample-looking name must survive.
	lookalike := h.user("sample-lookalike", map[string]string{"ten_real": directory.RoleMember})
	if err := samples.Add(ctx, h.pool, h.id, h.dir); err != nil {
		t.Fatal(err)
	}

	// Leave the kinds of trail testing leaves.
	admin := h.sampleBrowser("sample-acme-admin")
	h.redeem(admin)
	a := h.app()
	status, body := a.tryLogin("sample-member", samples.Password)
	h.wantStatus(status, body, http.StatusOK)
	a.keep(body)
	web := h.browser()
	id, _ := web.startQR(t)
	a.claim(h.url + "/v1/qr/" + id)
	a.approve(id)
	if _, _, page := admin.post("/admin/tenants/"+samples.TenantAcme+"/invitations", url.Values{"role": {"member"}}); page == "" {
		t.Fatal("no invitation page")
	}
	joined, err := h.dir.CreateInvitation(ctx, "test", samples.TenantAcme, directory.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	realBrowser := h.browser()
	if st := realBrowser.signIn("real", testPassword, ""); st != http.StatusSeeOther {
		t.Fatalf("sign in real: %d", st)
	}
	if st, _, page := realBrowser.post("/v1/join", url.Values{"invite": {joined}}); st != http.StatusSeeOther {
		t.Fatalf("join: %d %s", st, page)
	}
	// A real session pointing at a sample tenant must lose only that pointer.
	form := redeem(realBrowser.code())
	form.Set("tenant", samples.TenantAcme)
	status, body = h.token(form)
	h.wantStatus(status, body, http.StatusOK)
	realRefresh := body["refresh_token"].(string)

	var auditBefore int
	if err := h.pool.QueryRow(ctx, "SELECT count(*) FROM auth.audit_log").Scan(&auditBefore); err != nil {
		t.Fatal(err)
	}
	removed, err := samples.Remove(ctx, h.pool)
	if err != nil {
		t.Fatal(err)
	}
	if removed.Users != len(samples.Accounts) || removed.Tenants != 2 {
		t.Errorf("removed = %+v", removed)
	}
	for _, q := range []string{
		"SELECT count(*) FROM auth.users WHERE sample",
		"SELECT count(*) FROM auth.user_identifiers WHERE value LIKE 'sample-%' AND value <> 'sample-lookalike'",
		"SELECT count(*) FROM auth.tenants WHERE id LIKE 'ten_sample-%'",
		"SELECT count(*) FROM auth.memberships WHERE tenant_id LIKE 'ten_sample-%'",
		"SELECT count(*) FROM auth.invitations",
		"SELECT count(*) FROM auth.devices",
		"SELECT count(*) FROM auth.qr_logins WHERE user_id IS NOT NULL",
		"SELECT count(*) FROM auth.platform_admins",
		"SELECT count(*) FROM auth.sessions WHERE active_tenant_id LIKE 'ten_sample-%'",
	} {
		var n int
		if err := h.pool.QueryRow(ctx, q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s = %d", q, n)
		}
	}

	var survivors, auditAfter int
	err = h.pool.QueryRow(ctx, "SELECT count(*) FROM auth.memberships WHERE user_id = ANY($1) AND tenant_id = 'ten_real'",
		[]string{real, lookalike}).Scan(&survivors)
	if err != nil || survivors != 2 {
		t.Errorf("real members left = %d, %v", survivors, err)
	}
	if err := h.pool.QueryRow(ctx, "SELECT count(*) FROM auth.audit_log").Scan(&auditAfter); err != nil {
		t.Fatal(err)
	}
	if auditAfter != auditBefore+1 {
		t.Errorf("audit rows %d -> %d", auditBefore, auditAfter)
	}
	if status := realBrowser.signIn("real", testPassword, ""); status != http.StatusSeeOther {
		t.Errorf("real user cannot sign in: %d", status)
	}
	if status, body := h.token(refresh(realRefresh)); status != http.StatusOK {
		t.Errorf("real session after removal: %d %v", status, body)
	}

	// Adding them again works, so a test run can start over.
	if err := samples.Add(ctx, h.pool, h.id, h.dir); err != nil {
		t.Errorf("add after remove: %v", err)
	}
}
