package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"t10-auth-server/internal/directory"
)

func authorizeFor(client, tenant string) string {
	q := url.Values{
		"response_type": {"code"}, "client_id": {client}, "redirect_uri": {testRedirect},
		"code_challenge": {challenge()}, "code_challenge_method": {"S256"}, "state": {"st"},
	}
	if tenant != "" {
		q.Set("tenant", tenant)
	}
	return "/v1/authorize?" + q.Encode()
}

// codeFrom reads the code from a redirect to the client.
func codeFrom(t *testing.T, status int, location, body string) string {
	t.Helper()
	target, err := url.Parse(location)
	if status != http.StatusFound || err != nil || !strings.HasPrefix(location, testRedirect) {
		t.Fatalf("no code: %d %q %s", status, location, body)
	}
	return target.Query().Get("code")
}

func (h *harness) redeemAs(client, code string) (int, map[string]any) {
	h.t.Helper()
	form := redeem(code)
	form.Set("client_id", client)
	return h.token(form)
}

func (h *harness) activeTenant(token any) any {
	h.t.Helper()
	status, access := h.do("GET", "/v1/me/access", token.(string), nil)
	h.wantStatus(status, access, http.StatusOK)
	return access["active_tenant"]
}

func pickerFixture(t *testing.T) *harness {
	t.Helper()
	h, _ := adminFixture(t, false)
	h.user("both", map[string]string{"ten_acme": directory.RoleMember, "ten_other": directory.RoleAdmin})
	return h
}

func TestPickerListsTenantsAndTheChoiceReachesTheToken(t *testing.T) {
	h := pickerFixture(t)
	b := h.signedIn("both")
	status, location, body := b.get(authorizeFor(testPickerClient, ""))
	wantPage(t, status, body, http.StatusOK, "Choose a tenant", "ten_acme", "ten_other")
	if location != "" {
		t.Fatalf("picker redirected to %q", location)
	}
	status, location, body = b.get(authorizeFor(testPickerClient, "ten_other"))
	code := codeFrom(t, status, location, body)
	status, tokens := h.redeemAs(testPickerClient, code)
	h.wantStatus(status, tokens, http.StatusOK)
	if got := h.activeTenant(tokens["access_token"]); got != "ten_other" {
		t.Errorf("active tenant = %v", got)
	}
}

func TestPickerStaysOutOfTheWayWhenThereIsNothingToPick(t *testing.T) {
	h := pickerFixture(t)
	b := h.signedIn("grace")
	status, location, body := b.get(authorizeFor(testPickerClient, ""))
	status, tokens := h.redeemAs(testPickerClient, codeFrom(t, status, location, body))
	h.wantStatus(status, tokens, http.StatusOK)
	if got := h.activeTenant(tokens["access_token"]); got != "ten_acme" {
		t.Errorf("active tenant = %v", got)
	}
}

func TestPickerTreatsSomeoneElsesTenantAsNamingNone(t *testing.T) {
	h := pickerFixture(t)
	h.tenant("ten_third")

	// With several, they're asked. The page says nothing about the tenant they named.
	several := h.signedIn("both")
	status, _, body := several.get(authorizeFor(testPickerClient, "ten_third"))
	wantPage(t, status, body, http.StatusOK, "Choose a tenant")
	if strings.Contains(body, "ten_third") && !strings.Contains(body, "tenant=ten_acme") {
		t.Errorf("no way forward: %s", body)
	}

	// With one, they go on to their own, and the same is true of a tenant that doesn't exist.
	one := h.signedIn("grace")
	for _, named := range []string{"ten_third", "ten_nowhere"} {
		status, location, body := one.get(authorizeFor(testPickerClient, named))
		status, tokens := h.redeemAs(testPickerClient, codeFrom(t, status, location, body))
		h.wantStatus(status, tokens, http.StatusOK)
		if got := h.activeTenant(tokens["access_token"]); got != "ten_acme" {
			t.Errorf("named %s: active tenant = %v", named, got)
		}
	}
}

func TestAPickedTenantIsCheckedAgainWhenTheCodeIsSpent(t *testing.T) {
	h := pickerFixture(t)
	b := h.signedIn("both")
	status, location, body := b.get(authorizeFor(testPickerClient, "ten_other"))
	code := codeFrom(t, status, location, body)
	if _, err := h.pool.Exec(h.t.Context(), `UPDATE auth.memberships SET status = 'inactive' WHERE tenant_id = 'ten_other' AND user_id = $1`, h.userID("both")); err != nil {
		t.Fatal(err)
	}
	status, tokens := h.redeemAs(testPickerClient, code)
	if status != http.StatusForbidden {
		t.Fatalf("left the tenant, still got %d %v", status, tokens)
	}
}

func TestPickerSaysWhichTenantsNeedASecondFactor(t *testing.T) {
	h := pickerFixture(t)
	if _, err := h.pool.Exec(h.t.Context(), `UPDATE auth.tenants SET require_mfa = true WHERE id = 'ten_other'`); err != nil {
		t.Fatal(err)
	}
	b := h.signedIn("both")
	status, _, body := b.get(authorizeFor(testPickerClient, ""))
	wantPage(t, status, body, http.StatusOK, "Needs a second factor")
	if strings.Count(body, "Needs a second factor") != 1 {
		t.Errorf("marked more than the one tenant: %s", body)
	}
	status, location, page := b.get(authorizeFor(testPickerClient, "ten_other"))
	status, tokens := h.redeemAs(testPickerClient, codeFrom(t, status, location, page))
	if status != http.StatusForbidden || tokens["error"] != "mfa_required" {
		t.Fatalf("redeem without a factor: %d %v", status, tokens)
	}
}

func TestClientWithNoTenantSignsInAndRefreshesWithout(t *testing.T) {
	h := pickerFixture(t)
	// A tenant's policy has no say here, and refreshing is where a session would otherwise trip on it.
	if _, err := h.pool.Exec(h.t.Context(), `UPDATE auth.tenants SET require_mfa = true WHERE id = 'ten_other'`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"both", "grace"} {
		b := h.signedIn(name)
		status, location, body := b.get(authorizeFor(testNoTenantClient, ""))
		status, tokens := h.redeemAs(testNoTenantClient, codeFrom(t, status, location, body))
		h.wantStatus(status, tokens, http.StatusOK)
		if got := h.activeTenant(tokens["access_token"]); got != "" {
			t.Errorf("%s: active tenant = %v", name, got)
		}
		form := refresh(tokens["refresh_token"].(string))
		form.Set("client_id", testNoTenantClient)
		status, again := h.token(form)
		h.wantStatus(status, again, http.StatusOK)
		if got := h.activeTenant(again["access_token"]); got != "" {
			t.Errorf("%s after refresh: active tenant = %v", name, got)
		}
	}
}

func TestClientThatNamesItsOwnTenantIsUnchanged(t *testing.T) {
	h := pickerFixture(t)
	b := h.signedIn("both")
	status, location, body := b.get(authorizePath("st"))
	code := codeFrom(t, status, location, body)
	status, tokens := h.token(redeem(code))
	if status != http.StatusBadRequest || !strings.Contains(tokens["error_description"].(string), "name a tenant") {
		t.Fatalf("no tenant named: %d %v", status, tokens)
	}
	form := redeem(code)
	form.Set("tenant", "ten_acme")
	status, tokens = h.token(form)
	h.wantStatus(status, tokens, http.StatusOK)
	if got := h.activeTenant(tokens["access_token"]); got != "ten_acme" {
		t.Errorf("active tenant = %v", got)
	}
}
