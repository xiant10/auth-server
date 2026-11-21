package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"auth-server/internal/directory"
	"auth-server/internal/identity"
)

func TestPreferencesFollowThePerson(t *testing.T) {
	h, _ := adminFixture(t, false)
	token, _ := h.redeem(h.signedIn("grace"))
	status, prefs := h.do("GET", "/v1/me/preferences", token, nil)
	h.wantStatus(status, prefs, http.StatusOK)
	if prefs["language"] != nil || prefs["theme"] != nil || fmt.Sprint(prefs["languages"]) != "[en zh-Hans]" {
		t.Errorf("nothing chosen yet, and every language offered: %v", prefs)
	}
	status, prefs = h.do("PUT", "/v1/me/preferences", token, map[string]string{"theme": "dark"})
	h.wantStatus(status, prefs, http.StatusOK)
	status, prefs = h.do("PUT", "/v1/me/preferences", token, map[string]string{"language": "zh-Hans"})
	h.wantStatus(status, prefs, http.StatusOK)
	if prefs["theme"] != "dark" || prefs["language"] != "zh-Hans" {
		t.Errorf("a change keeps the other field: %v", prefs)
	}
	for _, bad := range []map[string]string{{"theme": "blue"}, {"language": "fr"}} {
		if status, body := h.do("PUT", "/v1/me/preferences", token, bad); status != http.StatusBadRequest {
			t.Errorf("%v: %d %v", bad, status, body)
		}
	}
	if status, _ := h.do("GET", "/v1/me/preferences", "", nil); status != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", status)
	}
}

// langAfterSignIn is the language the app is told to open in, from the code redirect.
func langAfterSignIn(t *testing.T, b *browser, uiLocales string) string {
	t.Helper()
	path := authorizePath("st")
	if uiLocales != "" {
		path += "&ui_locales=" + uiLocales
	}
	status, location, body := b.get(path)
	if status != http.StatusFound {
		t.Fatalf("authorize: %d %s", status, body)
	}
	target, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	return target.Query().Get("lang")
}

// chooseOnAccount saves a language as the account page does.
func (b *browser) chooseOnAccount(t *testing.T, lang string) (int, string) {
	t.Helper()
	status, _, body := b.post(accountPath, url.Values{"action": {"language"}, "lang": {lang}})
	return status, body
}

func TestTheAccountsLanguageOpensEveryApp(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.signedIn("grace")
	// Nothing chosen: the app is told nothing, so it shows the browser's language, and
	// nothing is saved for it.
	if got := langAfterSignIn(t, b, "zh-Hans"); got != "" {
		t.Errorf("a guess was handed on: %q", got)
	}
	token, _ := h.redeem(b)
	if _, prefs := h.do("GET", "/v1/me/preferences", token, nil); prefs["language"] != nil {
		t.Errorf("a guess was saved: %v", prefs)
	}
	// Chosen on the account page: every app opens in it, whatever it had before.
	if status, body := b.chooseOnAccount(t, "zh-Hans"); status != http.StatusOK {
		t.Fatalf("choose: %d %s", status, body)
	}
	if got := langAfterSignIn(t, b, "en"); got != "zh-Hans" {
		t.Errorf("a stale app language won: %q", got)
	}
	if _, prefs := h.do("GET", "/v1/me/preferences", token, nil); prefs["language"] != "zh-Hans" {
		t.Errorf("not saved: %v", prefs)
	}
}

func TestALanguageChosenOnTheSignInPageIsNotSaved(t *testing.T) {
	h, _ := adminFixture(t, false)
	first := h.signedIn("grace")
	token, _ := h.redeem(first)
	first.chooseOnAccount(t, "en")

	b := h.browser()
	b.post("/v1/language", url.Values{"lang": {"zh-Hans"}, "next": {"/v1/signin"}})
	_, body := b.getIn(t, "/v1/signin", "en")
	wantPage(t, http.StatusOK, body, http.StatusOK, `<html lang="zh-Hans">`)
	if status := b.signIn("grace", testPassword, ""); status != http.StatusSeeOther {
		t.Fatalf("sign in: %d", status)
	}
	if got := langAfterSignIn(t, b, ""); got != "en" {
		t.Errorf("the sign-in page's language beat the account's: %q", got)
	}
	if _, prefs := h.do("GET", "/v1/me/preferences", token, nil); prefs["language"] != "en" {
		t.Errorf("the sign-in page's language was saved: %v", prefs)
	}
}

func TestADeploymentWithOneLanguage(t *testing.T) {
	h := newHarness(t, false, "zh-Hans")
	h.tenant("ten_acme")
	h.user("grace", map[string]string{"ten_acme": directory.RoleMember})
	b := h.signedIn("grace")
	token, _ := h.redeem(b)
	// Nobody chooses: everyone has it.
	status, prefs := h.do("GET", "/v1/me/preferences", token, nil)
	h.wantStatus(status, prefs, http.StatusOK)
	if prefs["language"] != "zh-Hans" || fmt.Sprint(prefs["languages"]) != "[zh-Hans]" {
		t.Errorf("preferences: %v", prefs)
	}
	if status, body := h.do("PUT", "/v1/me/preferences", token, map[string]string{"language": "en"}); status != http.StatusBadRequest {
		t.Errorf("saved a language not offered: %d %v", status, body)
	}
	if got := langAfterSignIn(t, b, "en"); got != "zh-Hans" {
		t.Errorf("app opens in %q", got)
	}
	// The account page says so, and offers no choice.
	_, body := b.getIn(t, accountPath, "en-US")
	wantPage(t, http.StatusOK, body, http.StatusOK, `<html lang="zh-Hans">`, `data-testid="language-fixed"`, "由本系统统一设置")
	if strings.Contains(body, `name="lang"`) {
		t.Error("the account page offers a language")
	}
	if status, _ := b.chooseOnAccount(t, "en"); status != http.StatusBadRequest {
		t.Errorf("account page saved a language not offered: %d", status)
	}
	// Signed out, the pages show it, with no switch.
	_, body = h.browser().getIn(t, "/v1/signin", "en-US")
	wantPage(t, http.StatusOK, body, http.StatusOK, `<html lang="zh-Hans">`)
	if strings.Contains(body, `action="/v1/language"`) {
		t.Error("the sign-in page offers a switch")
	}
}

func TestALanguageNoLongerOfferedIsKept(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.signedIn("grace")
	token, _ := h.redeem(b)
	b.chooseOnAccount(t, "en")
	// The same database, now offering Chinese alone.
	narrowed := identity.NewService(identity.Options{Pool: h.pool, Languages: []string{"zh-Hans"}})
	id := h.userID("grace")
	if prefs, err := narrowed.GetPreferences(context.Background(), id); err != nil || prefs.Language != "zh-Hans" {
		t.Errorf("narrowed: %+v %v", prefs, err)
	}
	// Offering both again gives the choice back.
	if _, prefs := h.do("GET", "/v1/me/preferences", token, nil); prefs["language"] != "en" {
		t.Errorf("widened: %v", prefs)
	}
}

func TestAServiceReadsHowAPersonLikesToBeGreeted(t *testing.T) {
	h, id := adminFixture(t, false)
	token, _ := h.redeem(h.signedIn("grace"))
	status, prefs := h.do("PUT", "/v1/me/preferences", token, map[string]string{"greeting": "simple"})
	h.wantStatus(status, prefs, http.StatusOK)
	if status, body := h.do("PUT", "/v1/me/preferences", token, map[string]string{"greeting": "loud"}); status != http.StatusBadRequest {
		t.Errorf("unknown greeting: %d %v", status, body)
	}
	status, prefs = h.do("GET", "/v1/users/"+id+"/preferences", h.serviceToken(otherService), nil)
	h.wantStatus(status, prefs, http.StatusOK)
	if prefs["greeting"] != "simple" {
		t.Errorf("service read: %v", prefs)
	}
	if status, _ := h.do("GET", "/v1/users/"+id+"/preferences", token, nil); status != http.StatusUnauthorized && status != http.StatusForbidden {
		t.Errorf("a user token reads only its own, at /v1/me: %d", status)
	}
	if status, _ := h.do("GET", "/v1/users/usr_nobody/preferences", h.serviceToken(otherService), nil); status != http.StatusNotFound {
		t.Errorf("unknown user: %d", status)
	}
}
