package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/directory"
)

// handlerText finds the sentences and page titles that a file's Go code hands to
// the admin pages. Everything else there, such as a header name, isn't one.
func handlerText(t *testing.T, file string, funcs ...string) []string {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	sentence := regexp.MustCompile(`^[A-Z][a-z'-]*( |\.|$)`)
	var found []string
	ast.Inspect(parsed, func(n ast.Node) bool {
		// A file with named functions has other pages' text in the rest of it.
		if fn, ok := n.(*ast.FuncDecl); ok && len(funcs) > 0 && !slices.Contains(funcs, fn.Name.Name) {
			return false
		}
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if text, err := strconv.Unquote(lit.Value); err == nil && sentence.MatchString(text) {
				found = append(found, text)
			}
		}
		return true
	})
	return found
}

func TestChineseCatalogIsComplete(t *testing.T) {
	used := map[string]bool{}
	for _, m := range regexp.MustCompile(`\bt "((?:[^"\\]|\\.)*)"`).FindAllStringSubmatch(pagesHTML, -1) {
		used[m[1]] = true
	}
	for _, text := range handlerText(t, "admin.go", "handleAdmin") {
		used[text] = true
	}
	for _, text := range handlerText(t, "pages.go") {
		used[text] = true
	}
	delete(used, "Origin") // A header, read in pages.go.
	// Stored values reach the page through {{t .Status}} and the like.
	for _, value := range []string{
		directory.TenantActive, directory.TenantSuspended, directory.RoleAdmin, directory.RoleMember,
		directory.MemberActive, "inactive", "department", "team", audit.Success, audit.Denied,
		"username", "phone", "email",
	} {
		used[value] = true
	}
	if len(used) < 100 {
		t.Fatalf("found only %d strings", len(used))
	}
	verb := regexp.MustCompile(`%(\[\d\])?[sd]`)
	for _, text := range slices.Sorted(maps.Keys(used)) {
		zh, ok := zhText[text]
		if !ok {
			t.Errorf("no translation for %q", text)
			continue
		}
		if len(verb.FindAllString(text, -1)) != len(verb.FindAllString(zh, -1)) {
			t.Errorf("%q and %q take different values", text, zh)
		}
	}
	for _, text := range slices.Sorted(maps.Keys(zhText)) {
		if !used[text] {
			t.Errorf("translation of %q is unused", text)
		}
	}
}

// TestChinesePagesHaveNoEnglish catches text a template shows without t. It needs
// no database: text from handlers is the catalog test's job.
func TestChinesePagesHaveNoEnglish(t *testing.T) {
	markup := regexp.MustCompile(`(?s)<style.*?</style>|<script.*?</script>|<[^>]*>`)
	english := regexp.MustCompile(`[A-Za-z]{2,}`)
	for _, open := range []bool{true, false} {
		for _, name := range []string{"signin", "register", "codes", "recover", "reset", "join", "done", "problem", "totp", "account"} {
			var page strings.Builder
			if err := pagesZH.ExecuteTemplate(&page, name, pageData{Open: open, Invite: "x", Here: "/v1/signin"}); err != nil {
				t.Fatal(err)
			}
			text := strings.ReplaceAll(markup.ReplaceAllString(page.String(), ""), "English", "")
			if found := english.FindAllString(text, -1); len(found) > 0 {
				t.Errorf("%s has English: %q", name, found)
			}
		}
	}
}

func TestSignedOutPagesFollowTheBrowserLanguage(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.browser()
	for path, want := range map[string]string{
		"/v1/signin":                "用户名、手机号或邮箱",
		"/v1/register":              "仅限受邀注册",
		"/v1/recover":               "重置密码",
		"/v1/reset?token=x":         "设置新密码",
		"/v1/authorize?client_id=x": "未知的客户端或重定向地址",
	} {
		status, body := b.getIn(t, path, "zh-CN")
		if !strings.Contains(body, `<html lang="zh-Hans">`) || !strings.Contains(body, want) {
			t.Errorf("%s: %d %s", path, status, body)
		}
	}
	status, body := b.getIn(t, "/v1/signin", "en")
	wantPage(t, status, body, http.StatusOK, `<html lang="en">`, "Username, phone or email")
}

func TestLanguageSwitchWorksSignedOut(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.browser()
	const page = "/v1/reset?token=abc"
	status, body := b.getIn(t, page, "en")
	wantPage(t, status, body, http.StatusOK, `action="/v1/language"`, `name="next" value="/v1/reset?token=abc"`)
	if location := b.choose(t, langZH, page); location != page {
		t.Errorf("sent to %q", location)
	}
	status, body = b.getIn(t, "/v1/signin", "en")
	wantPage(t, status, body, http.StatusOK, `<html lang="zh-Hans">`, "或使用 t10 应用扫码", "批准前，请先在应用中核对登录请求。")

	status, _, body = b.post("/v1/signin", url.Values{"name": {"nobody"}, "password": {"wrong-password"}})
	wantPage(t, status, body, http.StatusUnauthorized, "登录名、密码或验证码错误", `action="/v1/language"`)
}

func TestLanguageSwitchLeavesSignedOutPagesOnTheSite(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.browser()
	for _, next := range []string{"https://evil.example/v1/signin", "//evil.example/v1/signin", "/v1/../v1/signin/qr"} {
		if location := b.choose(t, langZH, next); location != defaultNext {
			t.Errorf("next %q sent to %q", next, location)
		}
	}
}

func TestNoLanguageSwitchBesideRecoveryCodes(t *testing.T) {
	h, _ := adminFixture(t, true)
	status, _, body := h.browser().post("/v1/register", url.Values{"name": {"newcomer"}, "password": {testPassword}})
	wantPage(t, status, body, http.StatusOK, "Save these recovery codes")
	if strings.Contains(body, `action="/v1/language"`) {
		t.Error("switch offered beside recovery codes")
	}
}

func TestAcceptedLang(t *testing.T) {
	for header, want := range map[string]string{
		"":                           langEN,
		"fr-FR":                      langEN,
		"zh-CN,zh;q=0.9,en;q=0.8":    langZH,
		"en-US,en;q=0.9,zh-CN;q=0.8": langEN,
		"en;q=0.5, zh-TW;q=0.9":      langZH,
		"fr, zh":                     langZH,
		"zhx":                        langEN,
		"zh;q=bad":                   langEN,
		"zh;q=0":                     langEN,
	} {
		if got := acceptedLang(header); got != want {
			t.Errorf("acceptedLang(%q) = %q, want %q", header, got, want)
		}
	}
}

func (b *browser) getIn(t *testing.T, path, acceptLanguage string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("GET", b.h.url+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Language", acceptLanguage)
	resp, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	status, _, body := readPage(t, resp)
	return status, body
}

func TestAccountFollowsTheBrowserLanguage(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.signedIn("boss")
	status, body := b.getIn(t, "/v1/account", "zh-CN,zh;q=0.9")
	wantPage(t, status, body, http.StatusOK, `<html lang="zh-Hans">`, "组织设置", "修改密码")
	if strings.Contains(body, "Organization settings") {
		t.Error("English left on the Chinese page")
	}
	status, body = b.getIn(t, "/v1/account", "en-US")
	wantPage(t, status, body, http.StatusOK, `<html lang="en">`, "Organization settings")

	status, body = h.signedIn("grace").getIn(t, "/admin", "zh")
	wantPage(t, status, body, http.StatusForbidden, "无权访问", "你在这里没有可管理的内容")
}

// choose presses the language switch and returns where it was sent.
func (b *browser) choose(t *testing.T, lang, next string) string {
	t.Helper()
	status, location, body := b.post("/v1/language", url.Values{"lang": {lang}, "next": {next}})
	if status != http.StatusSeeOther {
		t.Fatalf("language: %d %s", status, body)
	}
	return location
}

func TestLanguageChoiceBeatsTheBrowser(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.signedIn("boss")
	const page = "/v1/account"
	status, body := b.getIn(t, page, "en")
	wantPage(t, status, body, http.StatusOK, `name="next" value="/v1/account"`)

	if location := b.choose(t, langZH, page); location != page {
		t.Errorf("sent to %q", location)
	}
	status, body = b.getIn(t, page, "en")
	wantPage(t, status, body, http.StatusOK, `<html lang="zh-Hans">`, "修改密码")
	b.choose(t, langEN, page)
	status, body = b.getIn(t, page, "zh")
	wantPage(t, status, body, http.StatusOK, `<html lang="en">`, "Change password")

	b.choose(t, "klingon", page)
	status, body = b.getIn(t, page, "en")
	wantPage(t, status, body, http.StatusOK, `<html lang="en">`)
}

func TestLanguageSwitchStaysOnTheSite(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.signedIn("boss")
	for _, next := range []string{"https://evil.example/admin", "//evil.example/admin", "/admin/../v1/token"} {
		if location := b.choose(t, langZH, next); location != defaultNext {
			t.Errorf("next %q sent to %q", next, location)
		}
	}
}

func TestLanguageSwitchNeedsSameOrigin(t *testing.T) {
	h, _ := adminFixture(t, false)
	b := h.signedIn("boss")
	req, err := http.NewRequest("POST", h.url+"/v1/language", strings.NewReader("lang=zh-Hans&next=/admin"))
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

func TestAccountPageStaysUnframeable(t *testing.T) {
	h, _ := adminFixture(t, false)
	resp, err := h.signedIn("boss").client.Get(h.url + "/v1/account")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("account page can be framed")
	}
}
