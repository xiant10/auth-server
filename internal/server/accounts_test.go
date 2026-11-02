package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/identity"
)

const (
	testClientID     = "t10-mac-client"
	testMobileClient = "t10-mobile"
	testRedirect     = "http://127.0.0.1:53124/callback"
	testVerifier     = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

func testClients() []identity.Client {
	return []identity.Client{{
		ID: testClientID, Type: identity.ClientPublic, RedirectURIs: []string{"http://127.0.0.1/callback"},
		IdleTTL: 720 * time.Hour, AbsoluteTTL: 2160 * time.Hour,
	}, {
		ID: testMobileClient, Name: "t10 mobile app", Type: identity.ClientPublic, DirectLogin: true, IdleTTL: 2160 * time.Hour,
	}}
}

func TestSafeNext(t *testing.T) {
	tests := map[string]string{
		"/v1/authorize?client_id=x": "/v1/authorize?client_id=x",
		"/v1/join?invite=a":         "/v1/join?invite=a",
		"/v1/account":               "/v1/account",
		"":                          defaultNext,
		"/v1/token":                 defaultNext,
		"https://evil.example/":     defaultNext,
		"//evil.example/v1/account": defaultNext,
		"/\\evil.example":           defaultNext,
		"javascript:alert(1)":       defaultNext,
	}
	for input, want := range tests {
		if got := safeNext(input); got != want {
			t.Errorf("safeNext(%q) = %q", input, got)
		}
	}
}

// browser is a cookie-holding client that sends a same-origin Origin header
// and does not follow redirects.
type browser struct {
	h      *harness
	client *http.Client
}

func (h *harness) browser() *browser {
	jar, err := cookiejar.New(nil)
	if err != nil {
		h.t.Fatal(err)
	}
	return &browser{h: h, client: &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (b *browser) get(path string) (int, string, string) {
	b.h.t.Helper()
	resp, err := b.client.Get(b.h.url + path)
	if err != nil {
		b.h.t.Fatal(err)
	}
	return readPage(b.h.t, resp)
}

func (b *browser) post(path string, form url.Values) (int, string, string) {
	b.h.t.Helper()
	req, err := http.NewRequest("POST", b.h.url+path, strings.NewReader(form.Encode()))
	if err != nil {
		b.h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.h.url)
	resp, err := b.client.Do(req)
	if err != nil {
		b.h.t.Fatal(err)
	}
	return readPage(b.h.t, resp)
}

func readPage(t *testing.T, resp *http.Response) (int, string, string) {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header.Get("Location"), string(body)
}

var (
	codePattern   = regexp.MustCompile(`<li><code>([a-z2-7-]+)</code></li>`)
	secretPattern = regexp.MustCompile(`<p><code>([A-Z2-7]+)</code></p>`)
)

// register signs up through the page and returns the recovery codes.
func (b *browser) register(name, invite string) []string {
	b.h.t.Helper()
	status, _, body := b.post("/v1/register", url.Values{"name": {name}, "password": {testPassword}, "invite": {invite}})
	if status != http.StatusOK {
		b.h.t.Fatalf("register %s: %d %s", name, status, body)
	}
	var codes []string
	for _, m := range codePattern.FindAllStringSubmatch(body, -1) {
		codes = append(codes, m[1])
	}
	return codes
}

func (b *browser) signIn(name, password, code string) int {
	b.h.t.Helper()
	status, _, _ := b.post("/v1/signin", url.Values{"name": {name}, "password": {password}, "code": {code}})
	return status
}

// enrollTOTP turns on TOTP and returns the secret.
func (b *browser) enrollTOTP() string {
	b.h.t.Helper()
	status, _, body := b.post("/v1/account", url.Values{"action": {"totp_start"}, "password": {testPassword}})
	if status != http.StatusOK {
		b.h.t.Fatalf("totp_start: %d %s", status, body)
	}
	secret := secretPattern.FindStringSubmatch(body)[1]
	status, _, body = b.post("/v1/account", url.Values{"action": {"totp_confirm"}, "code": {totpAt(b.h.t, secret, 0)}})
	if status != http.StatusOK {
		b.h.t.Fatalf("totp_confirm: %d %s", status, body)
	}
	return secret
}

func totpAt(t *testing.T, secret string, steps int) string {
	t.Helper()
	code, err := identity.TOTPCode(secret, time.Now().Add(time.Duration(steps)*30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func challenge() string {
	sum := sha256.Sum256([]byte(testVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func authorizePath(state string) string {
	return "/v1/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {testClientID}, "redirect_uri": {testRedirect},
		"code_challenge": {challenge()}, "code_challenge_method": {"S256"}, "state": {state},
	}.Encode()
}

// code runs /v1/authorize for a signed-in browser.
func (b *browser) code() string {
	b.h.t.Helper()
	status, location, body := b.get(authorizePath("st"))
	if status != http.StatusFound {
		b.h.t.Fatalf("authorize: %d %s", status, body)
	}
	target, err := url.Parse(location)
	if err != nil || !strings.HasPrefix(location, testRedirect) || target.Query().Get("state") != "st" {
		b.h.t.Fatalf("redirect = %q", location)
	}
	return target.Query().Get("code")
}

func (h *harness) token(form url.Values) (int, map[string]any) {
	h.t.Helper()
	resp, err := http.PostForm(h.url+"/v1/token", form)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func redeem(code string) url.Values {
	return url.Values{
		"grant_type": {"authorization_code"}, "client_id": {testClientID}, "code": {code},
		"redirect_uri": {testRedirect}, "code_verifier": {testVerifier},
	}
}

func refresh(secret string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "client_id": {testClientID}, "refresh_token": {secret}}
}

func (h *harness) redeem(b *browser) (access, refreshToken string) {
	h.t.Helper()
	status, body := h.token(redeem(b.code()))
	h.wantStatus(status, body, http.StatusOK)
	return body["access_token"].(string), body["refresh_token"].(string)
}

func (h *harness) refreshOK(secret string) string {
	h.t.Helper()
	status, body := h.token(refresh(secret))
	h.wantStatus(status, body, http.StatusOK)
	return body["refresh_token"].(string)
}

func TestCodeFlow_RegisterThenAdmission(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()

	// Signed out, authorize goes to sign-in and keeps the request.
	status, location, _ := b.get(authorizePath("st"))
	if status != http.StatusFound || !strings.HasPrefix(location, "/v1/signin?next=") {
		t.Fatalf("authorize signed out: %d %s", status, location)
	}

	codes := b.register("ada@acme.example", "")
	if len(codes) != 10 {
		t.Fatalf("recovery codes = %d", len(codes))
	}
	access, refreshToken := h.redeem(b)
	if refreshToken == "" {
		t.Fatal("no session secret")
	}
	st, body := h.do("POST", "/v1/rooms/admission", access, map[string]string{"room": "standup"})
	h.wantStatus(st, body, http.StatusOK)
	if !strings.HasSuffix(body["room_name"].(string), "__standup") {
		t.Errorf("room_name = %v", body["room_name"])
	}
}

func TestCodeRefusals(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")

	code := b.code()
	wrongVerifier := redeem(code)
	wrongVerifier.Set("code_verifier", strings.Repeat("x", 43))
	wrongRedirect := redeem(code)
	wrongRedirect.Set("redirect_uri", "http://127.0.0.1:9/callback")
	missingVerifier := redeem(code)
	missingVerifier.Del("code_verifier")
	for name, form := range map[string]url.Values{"verifier": wrongVerifier, "redirect": wrongRedirect, "none": missingVerifier} {
		if status, body := h.token(form); status != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Errorf("%s: %d %v", name, status, body)
		}
	}

	// Refused attempts leave the code spendable; a replay then kills its session.
	status, body := h.token(redeem(code))
	h.wantStatus(status, body, http.StatusOK)
	issued := body["refresh_token"].(string)
	status, body = h.token(redeem(code))
	h.wantStatus(status, body, http.StatusBadRequest)
	status, body = h.token(refresh(issued))
	h.wantStatus(status, body, http.StatusBadRequest)
	if h.auditCount("session.refresh", "denied") != 1 {
		t.Error("code replay left no audit row")
	}
}

func TestAuthorizeRefusals(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()

	// A bad redirect gets a page, never a redirect.
	for _, path := range []string{
		"/v1/authorize?client_id=nobody&redirect_uri=" + url.QueryEscape(testRedirect),
		"/v1/authorize?client_id=" + testClientID + "&redirect_uri=" + url.QueryEscape("http://evil.example/callback"),
	} {
		status, location, _ := b.get(path)
		if status != http.StatusBadRequest || location != "" {
			t.Errorf("%s: %d %q", path, status, location)
		}
	}

	// PKCE is mandatory and S256 only.
	path := strings.Replace(authorizePath("st"), "code_challenge_method=S256", "code_challenge_method=plain", 1)
	status, location, _ := b.get(path)
	if status != http.StatusFound || !strings.Contains(location, "error=invalid_request") {
		t.Errorf("plain PKCE: %d %q", status, location)
	}
}

func TestRefreshRotation(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	_, s1 := h.redeem(b)

	// A lost response: S2 never arrives, so the client retries S1.
	s2 := h.refreshOK(s1)
	s3 := h.refreshOK(s1)
	if s2 == s3 {
		t.Fatal("retry reused a secret")
	}
	// Using the new secret spends S1.
	s4 := h.refreshOK(s3)
	status, body := h.token(refresh(s1))
	h.wantStatus(status, body, http.StatusBadRequest)
	// The replay ended the session, so even the newest secret is dead.
	status, body = h.token(refresh(s4))
	h.wantStatus(status, body, http.StatusBadRequest)
}

func TestRefreshAbandonedSecretIsAReplay(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	_, s1 := h.redeem(b)
	s2 := h.refreshOK(s1)
	h.refreshOK(s1) // Abandons S2.
	status, body := h.token(refresh(s2))
	h.wantStatus(status, body, http.StatusBadRequest)
	if h.auditCount("session.refresh", "denied") != 1 {
		t.Error("replay of an abandoned secret left no audit row")
	}
}

func TestRefreshGuessDoesNotRevoke(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	_, s1 := h.redeem(b)
	sessionID, _, _ := strings.Cut(s1, ".")

	// The session ID is in every JWT, so a guess must not end the session.
	status, body := h.token(refresh(sessionID + ".guess"))
	h.wantStatus(status, body, http.StatusBadRequest)
	h.refreshOK(s1)
}

func TestRefreshRechecksMembershipAndUser(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true)
	h.tenant("ten_acme")
	userID := h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	b := h.browser()
	if st := b.signIn("ada", testPassword, ""); st != http.StatusSeeOther {
		t.Fatalf("sign in: %d", st)
	}
	_, secret := h.redeem(b)
	secret = h.refreshOK(secret)

	inactive := directory.MemberInactive
	if _, err := h.dir.UpdateMember(ctx, "test", "ten_acme", userID, directory.MemberUpdate{Status: &inactive}); err != nil {
		t.Fatal(err)
	}
	status, body := h.token(refresh(secret))
	h.wantStatus(status, body, http.StatusForbidden)
}

func TestRevoke(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	access, secret := h.redeem(b)

	resp, err := http.PostForm(h.url+"/v1/revoke", url.Values{"client_id": {testClientID}, "refresh_token": {secret}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	status, body := h.token(refresh(secret))
	h.wantStatus(status, body, http.StatusBadRequest)
	status, body = h.do("POST", "/v1/rooms/admission", access, map[string]string{"room": "r"})
	h.wantStatus(status, body, http.StatusUnauthorized)
}

func TestCrossOriginPostRefused(t *testing.T) {
	h := newHarness(t, true)
	for _, origin := range []string{"", "https://evil.example"} {
		req, err := http.NewRequest("POST", h.url+"/v1/signin", strings.NewReader("name=ada&password=x"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("origin %q: %d", origin, resp.StatusCode)
		}
	}
}

func TestPagesEscapeInput(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	_, _, body := b.get("/v1/reset?token=" + url.QueryEscape(`"><script>alert(1)</script>`))
	if strings.Contains(body, "<script>") {
		t.Error("token reflected unescaped")
	}
	resp, err := http.Get(h.url + "/v1/signin")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("sign-in page can be framed")
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("pages are cacheable")
	}
	// Under no-referrer, browsers post forms with "Origin: null", and the
	// same-origin check then refuses every form.
	if got := resp.Header.Get("Referrer-Policy"); got != "same-origin" {
		t.Errorf("Referrer-Policy = %q", got)
	}
}

func TestRegistrationNeedsInvitationOutsideDevMode(t *testing.T) {
	h := newHarness(t, false)
	h.tenant("ten_acme")
	b := h.browser()

	status, _, _ := b.post("/v1/register", url.Values{"name": {"ada"}, "password": {testPassword}})
	if status != http.StatusForbidden {
		t.Fatalf("open registration: %d", status)
	}

	invite, err := h.dir.CreateInvitation(context.Background(), "test", "ten_acme", directory.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	b.register("ada", invite)
	access, _ := h.redeem(b)
	st, body := h.do("POST", "/v1/rooms/admission", access, map[string]string{"room": "r"})
	h.wantStatus(st, body, http.StatusOK)
	if body["room_name"] != "ten_acme__r" {
		t.Errorf("room_name = %v", body["room_name"])
	}

	// Single use, and a failed registration leaves no account behind.
	status, _, _ = h.browser().post("/v1/register", url.Values{"name": {"eve"}, "password": {testPassword}, "invite": {invite}})
	if status != http.StatusBadRequest {
		t.Errorf("reused invitation: %d", status)
	}
	if st := h.browser().signIn("eve", testPassword, ""); st != http.StatusUnauthorized {
		t.Errorf("rolled-back account signed in: %d", st)
	}
}

func TestExpiredInvitation(t *testing.T) {
	h := newHarness(t, false)
	h.tenant("ten_acme")
	invite, err := h.dir.CreateInvitation(context.Background(), "test", "ten_acme", directory.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(context.Background(), "UPDATE auth.invitations SET expires_at = now() - interval '1 minute'"); err != nil {
		t.Fatal(err)
	}
	status, _, _ := h.browser().post("/v1/register", url.Values{"name": {"ada"}, "password": {testPassword}, "invite": {invite}})
	if status != http.StatusBadRequest {
		t.Errorf("expired invitation: %d", status)
	}
}

func TestExistingUserJoinsByInvitation(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.tenant("ten_other")
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	invite, err := h.dir.CreateInvitation(context.Background(), "test", "ten_other", directory.RoleMember)
	if err != nil {
		t.Fatal(err)
	}

	b := h.browser()
	status, location, _ := b.get("/v1/join?invite=" + invite)
	if status != http.StatusSeeOther || !strings.HasPrefix(location, "/v1/signin?next=") {
		t.Fatalf("join signed out: %d %s", status, location)
	}
	b.signIn("ada", testPassword, "")
	if status, _, body := b.post("/v1/join", url.Values{"invite": {invite}}); status != http.StatusSeeOther {
		t.Fatalf("join: %d %s", status, body)
	}
	h.login("ada", "ten_other")
}

func TestRegistrationValidation(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	tests := []struct {
		name, password string
		want           int
	}{
		{"ADA", testPassword, http.StatusConflict},
		{"!!", testPassword, http.StatusBadRequest},
		{"grace", "short", http.StatusBadRequest},
		{"grace", "password123", http.StatusBadRequest},
	}
	for _, tt := range tests {
		status, _, _ := h.browser().post("/v1/register", url.Values{"name": {tt.name}, "password": {tt.password}})
		if status != tt.want {
			t.Errorf("%s/%s: %d", tt.name, tt.password, status)
		}
	}
}

func TestTOTP(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	secret := b.enrollTOTP()

	if st := h.browser().signIn("ada", testPassword, ""); st != http.StatusUnauthorized {
		t.Errorf("no code: %d", st)
	}
	if st := h.browser().signIn("ada", testPassword, "000000"); st != http.StatusUnauthorized {
		t.Errorf("wrong code: %d", st)
	}
	// Enrollment spent the current step, so the next one signs in, once.
	next := totpAt(t, secret, 1)
	if st := h.browser().signIn("ada", testPassword, next); st != http.StatusSeeOther {
		t.Errorf("right code: %d", st)
	}
	if st := h.browser().signIn("ada", testPassword, next); st != http.StatusUnauthorized {
		t.Errorf("replayed code: %d", st)
	}

	// The dev password grant must not be a way around the factor.
	status, body := h.do("POST", "/v1/token", "", map[string]string{"grant_type": "password", "username": "ada", "password": testPassword})
	h.wantStatus(status, body, http.StatusBadRequest)

	// The stored secret is encrypted.
	var sealed []byte
	if err := h.pool.QueryRow(context.Background(), "SELECT secret_encrypted FROM auth.mfa_factors").Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), secret) {
		t.Error("TOTP secret stored in the clear")
	}
}

func TestUnconfirmedTOTPCountsForNothing(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	if status, _, body := b.post("/v1/account", url.Values{"action": {"totp_start"}, "password": {testPassword}}); status != http.StatusOK {
		t.Fatalf("totp_start: %d %s", status, body)
	}
	if st := h.browser().signIn("ada", testPassword, ""); st != http.StatusSeeOther {
		t.Errorf("sign-in blocked by an unconfirmed factor: %d", st)
	}
}

func TestPlatformAdminNeedsMFAOutsideDevMode(t *testing.T) {
	h := newHarness(t, false)
	h.tenant("ten_acme")
	root := h.user("root", map[string]string{"ten_acme": directory.RoleMember})
	h.platformAdmin(root)
	b := h.browser()
	b.signIn("root", testPassword, "")
	access, _ := h.redeem(b)

	create := map[string]string{"id": "ten_new", "name": "New"}
	status, body := h.do("POST", "/v1/tenants", access, create)
	h.wantStatus(status, body, http.StatusForbidden)

	secret := b.enrollTOTP()
	// Enrolling ended the client session above, so sign in afresh.
	b2 := h.browser()
	if st := b2.signIn("root", testPassword, totpAt(t, secret, 1)); st != http.StatusSeeOther {
		t.Fatalf("sign in: %d", st)
	}
	access, _ = h.redeem(b2)
	status, body = h.do("POST", "/v1/tenants", access, create)
	h.wantStatus(status, body, http.StatusCreated)

	// A platform admin cannot drop the factor.
	if status, _, _ := b2.post("/v1/account", url.Values{"action": {"totp_disable"}, "password": {testPassword}, "code": {totpAt(t, secret, -1)}}); status == http.StatusOK {
		t.Error("platform admin turned off MFA")
	}
}

func TestTenantCanRequireMFA(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.user("boss", map[string]string{"ten_acme": directory.RoleAdmin})
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember})

	status, body := h.do("PATCH", "/v1/tenants/ten_acme", h.login("boss", ""), map[string]bool{"require_mfa": true})
	h.wantStatus(status, body, http.StatusOK)
	if body["id"] != "ten_acme" {
		t.Errorf("tenant = %v", body)
	}

	b := h.browser()
	b.signIn("ada", testPassword, "")
	status, body = h.token(redeem(b.code()))
	h.wantStatus(status, body, http.StatusForbidden)
	if body["error"] != "mfa_required" {
		t.Errorf("error = %v", body["error"])
	}

	b.enrollTOTP()
	status, body = h.token(redeem(b.code()))
	h.wantStatus(status, body, http.StatusOK)
}

func TestLockout(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	for range 5 {
		if st := h.browser().signIn("ada", "wrong-password", ""); st != http.StatusUnauthorized {
			t.Fatalf("wrong password: %d", st)
		}
	}
	if st := h.browser().signIn("ada", testPassword, ""); st != http.StatusUnauthorized {
		t.Errorf("locked account signed in: %d", st)
	}
	if h.auditCount("session.create", "denied") != 6 {
		t.Errorf("denied rows = %d", h.auditCount("session.create", "denied"))
	}

	// The lock is temporary.
	if _, err := h.pool.Exec(context.Background(), "UPDATE auth.credentials SET locked_until = now() - interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	if st := h.browser().signIn("ada", testPassword, ""); st != http.StatusSeeOther {
		t.Errorf("after lock: %d", st)
	}
	var failed int
	if err := h.pool.QueryRow(context.Background(), "SELECT failed_count FROM auth.credentials").Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != 0 {
		t.Errorf("failed_count = %d", failed)
	}
}

func TestSignInRateLimit(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	limit := identity.DefaultLimits().SignInAccount.Max
	last := 0
	for range limit + 1 {
		last = h.browser().signIn("nobody", "wrong-password", "")
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("status = %d", last)
	}
}

func TestRecovery(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	codes := b.register("ada", "")
	_, secret := h.redeem(b)

	const newPassword = "a-brand-new-long-password"
	form := url.Values{"name": {"ada"}, "recovery_code": {codes[0]}, "new_password": {newPassword}}
	if status, _, body := h.browser().post("/v1/recover", form); status != http.StatusOK {
		t.Fatalf("recover: %d %s", status, body)
	}
	if st := h.browser().signIn("ada", newPassword, ""); st != http.StatusSeeOther {
		t.Errorf("new password: %d", st)
	}
	// Every session ended, the browser's and the client's.
	if status, location, _ := b.get("/v1/account"); status != http.StatusSeeOther || location == "" {
		t.Errorf("old browser session: %d", status)
	}
	status, body := h.token(refresh(secret))
	h.wantStatus(status, body, http.StatusBadRequest)

	// Each code works once.
	if status, _, _ := h.browser().post("/v1/recover", form); status != http.StatusUnauthorized {
		t.Errorf("reused code: %d", status)
	}
}

func TestRecoveryWithMFA(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	codes := b.register("ada", "")
	secret := b.enrollTOTP()
	const newPassword = "a-brand-new-long-password"

	// One code is not enough, and the refusal does not spend it.
	one := url.Values{"name": {"ada"}, "recovery_code": {codes[0]}, "new_password": {newPassword}}
	if status, _, _ := h.browser().post("/v1/recover", one); status != http.StatusUnauthorized {
		t.Fatalf("one code: %d", status)
	}

	// With TOTP, the factor stays.
	withTOTP := url.Values{"name": {"ada"}, "recovery_code": {codes[0]}, "code": {totpAt(t, secret, 1)}, "new_password": {newPassword}}
	if status, _, body := h.browser().post("/v1/recover", withTOTP); status != http.StatusOK {
		t.Fatalf("with TOTP: %d %s", status, body)
	}
	if st := h.browser().signIn("ada", newPassword, ""); st != http.StatusUnauthorized {
		t.Errorf("factor was dropped: %d", st)
	}

	// With a second code, the lost factor goes.
	two := url.Values{"name": {"ada"}, "recovery_code": {codes[1]}, "second_code": {codes[2]}, "new_password": {testPassword}}
	if status, _, body := h.browser().post("/v1/recover", two); status != http.StatusOK {
		t.Fatalf("two codes: %d %s", status, body)
	}
	if st := h.browser().signIn("ada", testPassword, ""); st != http.StatusSeeOther {
		t.Errorf("after two codes: %d", st)
	}
}

func TestAdminResetLinks(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.tenant("ten_other")
	root := h.user("root", nil)
	h.platformAdmin(root)
	h.user("boss", map[string]string{"ten_acme": directory.RoleAdmin})
	member := h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	coAdmin := h.user("coadmin", map[string]string{"ten_acme": directory.RoleAdmin})
	shared := h.user("shared", map[string]string{"ten_acme": directory.RoleMember, "ten_other": directory.RoleAdmin})
	both := h.user("both", map[string]string{"ten_acme": directory.RoleMember})
	h.platformAdmin(both)
	stranger := h.user("stranger", map[string]string{"ten_other": directory.RoleMember})
	boss, rootToken := h.login("boss", ""), h.login("root", "")

	// A tenant admin must not reach anything outside their tenant through a
	// shared account, or an account with more power than their own.
	for name, target := range map[string]string{"co-admin": coAdmin, "two tenants": shared, "platform admin": both, "other tenant": stranger} {
		status, body := h.do("POST", "/v1/tenants/ten_acme/members/"+target+"/reset-link", boss, nil)
		if status != http.StatusForbidden {
			t.Errorf("%s: %d %v", name, status, body)
		}
	}
	status, body := h.do("POST", "/v1/tenants/ten_acme/members/"+coAdmin+"/reset-link", rootToken, nil)
	h.wantStatus(status, body, http.StatusCreated)
	status, body = h.do("POST", "/v1/tenants/ten_acme/members/"+stranger+"/reset-link", rootToken, nil)
	h.wantStatus(status, body, http.StatusForbidden)

	status, body = h.do("POST", "/v1/tenants/ten_acme/members/"+member+"/reset-link", boss, nil)
	h.wantStatus(status, body, http.StatusCreated)
	link, err := url.Parse(body["reset_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	token := link.Query().Get("token")

	const newPassword = "a-brand-new-long-password"
	form := url.Values{"token": {token}, "new_password": {newPassword}}
	if status, _, body := h.browser().post("/v1/reset", form); status != http.StatusOK {
		t.Fatalf("reset: %d %s", status, body)
	}
	if status, _, _ := h.browser().post("/v1/reset", form); status != http.StatusBadRequest {
		t.Errorf("reused link: %d", status)
	}
	if st := h.browser().signIn("ada", newPassword, ""); st != http.StatusSeeOther {
		t.Errorf("new password: %d", st)
	}

	// Links expire.
	if _, err := h.pool.Exec(context.Background(), "UPDATE auth.reset_tokens SET used_at = NULL, expires_at = now() - interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := h.browser().post("/v1/reset", form); status != http.StatusBadRequest {
		t.Errorf("expired link: %d", status)
	}
}

func TestSignInNames(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	root := h.user("root", nil)
	h.platformAdmin(root)

	withAuth := func(action, name string) url.Values {
		return url.Values{"action": {action}, "name": {name}, "password": {testPassword}}
	}
	if status, _, body := b.post("/v1/account", withAuth("name_add", "+86 138 0013 8000")); status != http.StatusOK {
		t.Fatalf("add phone: %d %s", status, body)
	}
	if st := h.browser().signIn("13800138000", testPassword, ""); st != http.StatusSeeOther {
		t.Errorf("sign in by phone: %d", st)
	}
	if status, _, _ := b.post("/v1/account", url.Values{"action": {"name_add"}, "name": {"ada2"}, "password": {"wrong-password"}}); status != http.StatusUnauthorized {
		t.Errorf("add without current password: %d", status)
	}
	if status, _, _ := b.post("/v1/account", withAuth("name_remove", "ada")); status != http.StatusOK {
		t.Errorf("remove: %d", status)
	}
	if status, _, _ := b.post("/v1/account", withAuth("name_remove", "13800138000")); status != http.StatusBadRequest {
		t.Errorf("removed the last name: %d", status)
	}

	// A platform admin can release a disputed name for someone else to claim.
	status, body := h.do("POST", "/v1/identifiers/release", h.login("root", ""), map[string]string{"name": "+8613800138000"})
	h.wantStatus(status, body, http.StatusOK)
	h.browser().register("13800138000", "")
}

func TestChangePasswordKeepsOnlyThisSession(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	_, secret := h.redeem(b)
	other := h.browser()
	other.signIn("ada", testPassword, "")

	const newPassword = "a-brand-new-long-password"
	form := url.Values{"action": {"password"}, "password": {testPassword}, "new_password": {newPassword}}
	if status, _, body := b.post("/v1/account", form); status != http.StatusOK {
		t.Fatalf("change: %d %s", status, body)
	}
	if status, _, _ := b.get("/v1/account"); status != http.StatusOK {
		t.Errorf("this session: %d", status)
	}
	if status, _, _ := other.get("/v1/account"); status != http.StatusSeeOther {
		t.Errorf("other session: %d", status)
	}
	if status, body := h.token(refresh(secret)); status != http.StatusBadRequest {
		t.Errorf("client session: %d %v", status, body)
	}
}

func TestSignOut(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	_, secret := h.redeem(b)

	// A device sign-out leaves the client's own session alone.
	if status, _, _ := b.post("/v1/signout", url.Values{}); status != http.StatusSeeOther {
		t.Fatalf("sign out: %d", status)
	}
	if status, _, _ := b.get("/v1/account"); status != http.StatusSeeOther {
		t.Errorf("after sign-out: %d", status)
	}
	secret = h.refreshOK(secret)

	// Everywhere means everywhere.
	b.signIn("ada", testPassword, "")
	if status, _, _ := b.post("/v1/account", url.Values{"action": {"signout_all"}}); status != http.StatusSeeOther {
		t.Fatalf("sign out everywhere: %d", status)
	}
	status, body := h.token(refresh(secret))
	h.wantStatus(status, body, http.StatusBadRequest)
}

func TestTenantAdminRightsFollowTheActiveTenant(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.tenant("ten_other")
	h.user("boss", map[string]string{"ten_acme": directory.RoleAdmin, "ten_other": directory.RoleMember})

	inOther := h.login("boss", "ten_other")
	status, body := h.do("GET", "/v1/tenants/ten_acme/members", inOther, nil)
	h.wantStatus(status, body, http.StatusForbidden)

	inAcme := h.login("boss", "ten_acme")
	status, body = h.do("GET", "/v1/tenants/ten_acme/members", inAcme, nil)
	h.wantStatus(status, body, http.StatusOK)
}

func TestSessionCookieAttributes(t *testing.T) {
	for publicURL, want := range map[string][]string{
		"https://auth.example.com": {"__Host-t10_session=v", "Path=/", "HttpOnly", "Secure", "SameSite=Lax"},
		"http://localhost:8081":    {"t10_session=v", "Path=/", "HttpOnly", "SameSite=Lax"},
	} {
		rec := httptest.NewRecorder()
		New(Deps{PublicURL: publicURL}).setSessionCookie(rec, "v", 60)
		cookie := rec.Header().Get("Set-Cookie")
		for _, part := range want {
			if !strings.Contains(cookie, part) {
				t.Errorf("%s: %q lacks %q", publicURL, cookie, part)
			}
		}
		if strings.Contains(cookie, "Domain") {
			t.Errorf("%s: %q sets a domain", publicURL, cookie)
		}
	}
}

func TestRequestLogHoldsNoIDs(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/qr/{id}/claim", func(http.ResponseWriter, *http.Request) {})
	handler := logRequests(mux)
	for _, path := range []string{"/v1/qr/secret-id/claim", "/secret-path"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", path, nil))
	}
	if strings.Contains(logs.String(), "secret") {
		t.Errorf("logs = %s", logs.String())
	}
	if !strings.Contains(logs.String(), "/v1/qr/{id}/claim") {
		t.Errorf("logs lack the route: %s", logs.String())
	}
}
