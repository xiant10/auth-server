package server

import (
	"net/http"
	"net/url"
	"testing"
)

func TestPreferencesFollowThePerson(t *testing.T) {
	h, _ := adminFixture(t, false)
	token, _ := h.redeem(h.signedIn("grace"))
	status, prefs := h.do("GET", "/v1/me/preferences", token, nil)
	h.wantStatus(status, prefs, http.StatusOK)
	if len(prefs) != 0 {
		t.Errorf("nothing chosen yet: %v", prefs)
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

func TestTheAccountsLanguageOpensEveryApp(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.signedIn("grace")
	// Nothing saved: the app's own choice counts, and is saved for the next app.
	if got := langAfterSignIn(t, b, "zh-Hans"); got != "zh-Hans" {
		t.Errorf("first choice: %q", got)
	}
	token, _ := h.redeem(b)
	if _, prefs := h.do("GET", "/v1/me/preferences", token, nil); prefs["language"] != "zh-Hans" {
		t.Errorf("not saved: %v", prefs)
	}
	// Saved: an app that still has another language opens in the account's.
	if got := langAfterSignIn(t, b, "en"); got != "zh-Hans" {
		t.Errorf("a stale app language won: %q", got)
	}
	// Chosen on a page while signed in: saved at once.
	b.post("/v1/language", url.Values{"lang": {"en"}, "next": {"/v1/account"}})
	if got := langAfterSignIn(t, b, ""); got != "en" {
		t.Errorf("a choice on the account page: %q", got)
	}
}

func TestALanguageChosenOnTheSignInPageIsSaved(t *testing.T) {
	h, _ := adminFixture(t, false)
	first := h.signedIn("grace")
	token, _ := h.redeem(first)
	h.do("PUT", "/v1/me/preferences", token, map[string]string{"language": "en"})

	b := h.browser()
	b.post("/v1/language", url.Values{"lang": {"zh-Hans"}, "next": {"/v1/signin"}})
	if status := b.signIn("grace", testPassword, ""); status != http.StatusSeeOther {
		t.Fatalf("sign in: %d", status)
	}
	if got := langAfterSignIn(t, b, ""); got != "zh-Hans" {
		t.Errorf("chosen at sign-in: %q", got)
	}
	if _, prefs := h.do("GET", "/v1/me/preferences", token, nil); prefs["language"] != "zh-Hans" {
		t.Errorf("not saved: %v", prefs)
	}
	// Only once: the next sign-in in this browser follows the account again.
	h.do("PUT", "/v1/me/preferences", token, map[string]string{"language": "en"})
	if got := langAfterSignIn(t, b, ""); got != "en" {
		t.Errorf("the mark stayed: %q", got)
	}
}
