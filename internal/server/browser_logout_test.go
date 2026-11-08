package server

import (
	"crypto/sha256"
	"encoding/hex"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
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

const (
	testWebClient = "test-web"
	testWebSecret = "test-web-secret"
)

func testWebSecretHash() string {
	sum := sha256.Sum256([]byte(testWebSecret))
	return hex.EncodeToString(sum[:])
}

// webApp signs a confidential client in from this browser, as each web app does.
func (h *harness) webApp(b *browser) string {
	h.t.Helper()
	status, location, body := b.get(authorizeFor(testWebClient, ""))
	if status != http.StatusFound {
		h.t.Fatalf("authorize: %d %s", status, body)
	}
	target, err := url.Parse(location)
	if err != nil {
		h.t.Fatal(err)
	}
	form := redeem(target.Query().Get("code"))
	form.Set("client_id", testWebClient)
	form.Set("client_secret", testWebSecret)
	code, tokens := h.token(form)
	h.wantStatus(code, tokens, http.StatusOK)
	return tokens["access_token"].(string)
}

// One sign-out ends the browser's sign-in and every web app started from it. It
// leaves native apps, which sign in for themselves, and other browsers alone.
func TestSignOutEndsEveryWebAppInTheBrowser(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	first, second := h.webApp(b), h.webApp(b)
	native, _ := h.redeem(b)
	elsewhere := h.browser()
	elsewhere.signIn("ada", testPassword, "")
	other := h.webApp(elsewhere)
	status, body := h.do("POST", "/v1/me/browser-logout", first, map[string]string{"client_id": "test-workbench", "return_to": "https://work.example/signed-out"})
	if status != http.StatusOK {
		t.Fatalf("ticket: %d %v", status, body)
	}
	if status, target, _ := b.get("/v1/signout/complete?ticket=" + url.QueryEscape(body["ticket"].(string))); status != http.StatusSeeOther || target != "https://work.example/signed-out" {
		t.Fatalf("complete: %d %s", status, target)
	}
	for _, token := range []string{first, second} {
		if status, _ := h.do("GET", "/v1/me/session", token, nil); status != http.StatusUnauthorized {
			t.Fatalf("web app alive after sign-out: %d", status)
		}
	}
	for _, token := range []string{native, other} {
		if status, _ := h.do("GET", "/v1/me/session", token, nil); status != http.StatusOK {
			t.Fatalf("session outside this browser's web apps ended: %d", status)
		}
	}
	if status, _, _ := b.get("/v1/account"); status != http.StatusSeeOther {
		t.Fatalf("browser still signed in: %d", status)
	}
}

// An expired browser sign-in doesn't stop one sign-out reaching the apps.
func TestSignOutFromAnAppAfterTheHostedPageSignedOut(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	first, second := h.webApp(b), h.webApp(b)
	if status, _, _ := b.post("/v1/signout", url.Values{}); status != http.StatusSeeOther {
		t.Fatalf("hosted sign-out: %d", status)
	}
	for _, token := range []string{first, second} {
		if status, _ := h.do("GET", "/v1/me/session", token, nil); status != http.StatusUnauthorized {
			t.Fatalf("web app alive after hosted sign-out: %d", status)
		}
	}
}

func TestSignOutPageAsksOnlyWhenSignedIn(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	if status, target, _ := b.get("/v1/signout"); status != http.StatusSeeOther || !strings.Contains(target, "reason=signedout") {
		t.Fatalf("signed out: %d %s", status, target)
	}
	b.register("ada", "")
	status, _, body := b.get("/v1/signout")
	wantPage(t, status, body, http.StatusOK, "Sign out of t10?", `action="/v1/signout"`)
}

func TestSignInNamesTheApp(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	status, location, _ := b.get(authorizeFor(testWebClient, ""))
	if status != http.StatusFound {
		t.Fatalf("authorize: %d", status)
	}
	status, _, body := b.get(location)
	wantPage(t, status, body, http.StatusOK, "Sign in to Workbench")
	if strings.Contains(body, "Authenticator code") {
		t.Fatal("asked for a code before knowing the account has one")
	}
}

func TestSignInKeepsTheNameAfterAWrongPassword(t *testing.T) {
	h := newHarness(t, true)
	h.browser().register("ada", "")
	status, _, body := h.browser().post("/v1/signin", url.Values{"name": {"ada"}, "password": {"wrong-password"}})
	wantPage(t, status, body, http.StatusUnauthorized, "Wrong sign-in name or password.", `value="ada"`)
}

// The code is asked for on its own step, and only if the account has one. A wrong
// code stays on that step, and counts toward the account's lockout.
func TestSignInAsksForTheCodeOnItsOwnStep(t *testing.T) {
	h := newHarness(t, true)
	owner := h.browser()
	owner.register("ada", "")
	secret := owner.enrollTOTP()
	b := h.browser()
	status, _, body := b.post("/v1/signin", url.Values{"name": {"ada"}, "password": {"wrong-password"}})
	wantPage(t, status, body, http.StatusUnauthorized, "Wrong sign-in name or password.")
	status, _, body = b.post("/v1/signin", url.Values{"name": {"ada"}, "password": {testPassword}, "next": {"/v1/account"}})
	wantPage(t, status, body, http.StatusOK, "Enter your code", `name="code_ticket"`, `value="/v1/account"`)
	match := regexp.MustCompile(`name="code_ticket" value="([^"]+)"`).FindStringSubmatch(body)
	if match == nil {
		t.Fatal("no ticket")
	}
	form := url.Values{"code_ticket": {html.UnescapeString(match[1])}, "next": {"/v1/account"}}
	form.Set("code", "000000")
	status, _, body = b.post("/v1/signin", form)
	wantPage(t, status, body, http.StatusUnauthorized, "Try the newest one.", `name="code_ticket"`)
	form.Set("code", totpAt(t, secret, 1))
	status, target, _ := b.post("/v1/signin", form)
	if status != http.StatusSeeOther || target != "/v1/account" {
		t.Fatalf("right code: %d %s", status, target)
	}
	form.Set("code_ticket", "not-a-ticket")
	status, _, body = h.browser().post("/v1/signin", form)
	wantPage(t, status, body, http.StatusUnauthorized, "That took too long.")
}

func TestSignedInBrowserSkipsTheSignInPage(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	if status, target, _ := b.get("/v1/signin?next=/v1/account"); status != http.StatusSeeOther || target != "/v1/account" {
		t.Fatalf("got %d %s", status, target)
	}
	if status, _, _ := b.get("/v1/signin?reason=stepup"); status != http.StatusOK {
		t.Fatalf("step-up must still ask: %d", status)
	}
}

func TestLanguageGoesThroughSignIn(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	status, location, _ := b.get(authorizeFor(testWebClient, "") + "&ui_locales=zh-Hans&reason=signedout")
	if status != http.StatusFound || strings.Contains(location, "ui_locales") || !strings.Contains(location, "reason=signedout") {
		t.Fatalf("to sign-in: %d %s", status, location)
	}
	status, _, body := b.get(location)
	wantPage(t, status, body, http.StatusOK, "登录工作台", "您已退出此浏览器上的所有 t10 应用。")
	b.register("ada", "")
	if _, target, _ := b.get(authorizeFor(testWebClient, "")); !strings.Contains(target, "lang=zh-Hans") {
		t.Fatalf("back to the app: %s", target)
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
	if status, _, body := b.get("/v1/signout/complete?ticket=invalid"); status != http.StatusBadRequest || !strings.Contains(body, `action="/v1/signout"`) {
		t.Fatalf("invalid: %d", status)
	}
	if status, _ := h.do("POST", "/v1/me/browser-logout", access, map[string]string{"client_id": "test-workbench", "return_to": "https://evil.example/signed-out"}); status != http.StatusBadRequest {
		t.Fatalf("bad return: %d", status)
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
}

// A sign-out link that can't finish offers Sign out on a page whose post must carry
// this origin, so only the redirect back to the app hides the ticket from Referer.
func TestSignOutAgainPageCanPost(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	access, _ := h.redeem(b)
	policy := func(path string) (int, string) {
		t.Helper()
		resp, err := b.client.Get(h.url + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("Referrer-Policy")
	}
	if status, got := policy("/v1/signout/complete?ticket=expired"); status != http.StatusBadRequest || got != "same-origin" {
		t.Errorf("sign out again: %d %q", status, got)
	}
	_, body := h.do("POST", "/v1/me/browser-logout", access, map[string]string{"client_id": "test-workbench", "return_to": "https://work.example/signed-out"})
	if status, got := policy("/v1/signout/complete?ticket=" + url.QueryEscape(body["ticket"].(string))); status != http.StatusSeeOther || got != "no-referrer" {
		t.Errorf("back to the app: %d %q", status, got)
	}
}
