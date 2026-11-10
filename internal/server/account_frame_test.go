package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestTheAccountPageWearsTheFrame(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.signedIn("grace")
	status, _, body := b.get(accountPath)
	wantPage(t, status, body, http.StatusOK, `class="sidebar"`, `data-testid="rail-apps"`, `href="`+testWorkbenchURL+`/t/ten_acme/"`, `action="/v1/theme"`, `action="/v1/signout"`)
	if strings.Contains(body, `data-theme="`) {
		t.Errorf("no theme chosen, yet one is set")
	}
	b.post("/v1/theme", url.Values{"theme": {"dark"}, "next": {accountPath}})
	if _, _, body = b.get(accountPath); !strings.Contains(body, `data-theme="dark"`) {
		t.Errorf("the saved theme isn't drawn")
	}
}

func TestTheAccountPageGoesBackOnlyToThisDeploymentsApps(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.signedIn("grace")
	back := testWorkbenchURL + "/t/ten_acme/tasks"
	status, _, body := b.get(accountPath + "?return_to=" + url.QueryEscape(back))
	wantPage(t, status, body, http.StatusOK, `href="`+back+`"`, "Back to Workbench")
	// A form posted on the page keeps the way back.
	_, _, body = b.post(accountPath, url.Values{"action": {"display_name"}, "display_name": {"Grace"}})
	if !strings.Contains(body, "Back to Workbench") {
		t.Errorf("lost after a change")
	}
	other := h.signedIn("grace")
	_, _, body = other.get(accountPath + "?return_to=" + url.QueryEscape("https://evil.example/"))
	if strings.Contains(body, "evil.example") || strings.Contains(body, "Back to") {
		t.Errorf("went back to another site")
	}
}

func TestTheAccountPageListsAndEndsOtherBrowsers(t *testing.T) {
	h, _ := adminFixture(t, false)
	here := h.signedIn("grace")
	there := h.signedIn("grace")
	h.redeem(there) // a web app open on the other browser
	_, _, body := here.get(accountPath)
	if !strings.Contains(body, "This browser") || !strings.Contains(body, "Another browser") {
		t.Fatalf("sign-ins not listed: %s", body)
	}
	start := strings.Index(body, `name="signin" value="`)
	if start < 0 {
		t.Fatal("no way to end the other browser")
	}
	id := body[start+len(`name="signin" value="`):]
	id = id[:strings.Index(id, `"`)]
	_, _, body = here.post(accountPath, url.Values{"action": {"signin_end"}, "signin": {id}})
	if !strings.Contains(body, "That browser is signed out.") || strings.Contains(body, "Another browser") {
		t.Errorf("not ended: %s", body)
	}
	if status, _, _ := there.get(accountPath); status == http.StatusOK {
		t.Errorf("the other browser is still signed in")
	}
	if status, _, _ := here.get(accountPath); status != http.StatusOK {
		t.Errorf("this browser was signed out too: %d", status)
	}
}
