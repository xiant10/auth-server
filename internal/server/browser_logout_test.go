package server

import (
	"net/http"
	"net/url"
	"testing"

	"t10-auth-server/internal/identity"
)

func TestBrowserLogoutRedirect(t *testing.T) {
	client := identity.Client{Type: identity.ClientConfidential, RedirectURIs: []string{"https://work.example/auth/callback"}}
	for _, target := range []string{"https://evil.example/signed-out", "https://work.example.evil/signed-out", "https://user@work.example/signed-out", "http://work.example/signed-out", "https://work.example/signed-out?next=evil", "https://work.example/signed-out#x", "https://work.example/account", "//work.example/signed-out"} {
		if browserLogoutRedirect(client, target) {
			t.Errorf("accepted %q", target)
		}
	}
	if !browserLogoutRedirect(client, "https://work.example/signed-out") {
		t.Fatal("valid return rejected")
	}
	client.Type = identity.ClientPublic
	if browserLogoutRedirect(client, "https://work.example/signed-out") {
		t.Fatal("native client accepted")
	}
}

func TestBrowserLogoutEndsOnlyMatchingBrowser(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	access, _ := h.redeem(b)
	otherDevice := h.browser()
	otherDevice.signIn("ada", testPassword, "")
	stranger := h.browser()
	stranger.register("grace", "")
	status, body := h.do("POST", "/v1/me/browser-logout", access, map[string]string{"client_id": "test-workbench", "return_to": "https://work.example/signed-out"})
	if status != http.StatusOK {
		t.Fatalf("ticket: %d %v", status, body)
	}
	path := "/v1/signout/complete?ticket=" + url.QueryEscape(body["ticket"].(string))
	if status, _, _ := stranger.get(path); status != http.StatusForbidden {
		t.Fatalf("wrong user: %d", status)
	}
	if status, _, _ := b.get("/v1/signout/complete?ticket=invalid"); status != http.StatusBadRequest {
		t.Fatalf("invalid: %d", status)
	}
	if status, target, _ := b.get(path); status != http.StatusSeeOther || target != "https://work.example/signed-out" {
		t.Fatalf("complete: %d %s", status, target)
	}
	if status, _, _ := b.get("/v1/account"); status != http.StatusSeeOther {
		t.Fatalf("still signed in: %d", status)
	}
	for _, browser := range []*browser{otherDevice, stranger} {
		if status, _, _ := browser.get("/v1/account"); status != http.StatusOK {
			t.Fatalf("another session ended: %d", status)
		}
	}
	if status, _, _ := b.get(path); status != http.StatusSeeOther {
		t.Fatalf("retry signed-out browser: %d", status)
	}
	if status, _ := h.do("POST", "/v1/me/browser-logout", "", map[string]string{}); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated issuance: %d", status)
	}
	if status, _ := h.do("POST", "/v1/me/browser-logout", access, map[string]string{"client_id": "test-workbench", "return_to": "https://evil.example/signed-out"}); status != http.StatusBadRequest {
		t.Fatalf("bad return: %d", status)
	}
}
