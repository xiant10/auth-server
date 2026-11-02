package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/identity"
)

// These tests hold findings from the pre-review of rollout step 4 in place.

// tightPool makes the next harness use two connections, so any code that needs
// a second connection while holding a transaction deadlocks at once.
func tightPool(t *testing.T) {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	t.Setenv("TEST_DATABASE_URL", base+sep+"pool_max_conns=2")
}

// burst sends every body at once and fails on anything but 200, which is what a
// request stuck on the pool turns into when the client gives up.
func burst(t *testing.T, target, contentType string, bodies []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	statuses := make([]int, len(bodies))
	for i, body := range bodies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(body))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", contentType)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			statuses[i] = resp.StatusCode
		}()
	}
	wg.Wait()
	for i, status := range statuses {
		if status != http.StatusOK {
			t.Errorf("request %d = %d, want 200 (0 means it hung)", i, status)
		}
	}
}

func TestBurstOfRefreshesCannotExhaustThePool(t *testing.T) {
	tightPool(t)
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	bodies := make([]string, 8)
	for i := range bodies {
		_, secret := h.redeem(b)
		bodies[i] = refresh(secret).Encode()
	}
	burst(t, h.url+"/v1/token", "application/x-www-form-urlencoded", bodies)
}

func TestBurstOfCodeRedemptionsCannotExhaustThePool(t *testing.T) {
	tightPool(t)
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	bodies := make([]string, 8)
	for i := range bodies {
		bodies[i] = redeem(b.code()).Encode()
	}
	burst(t, h.url+"/v1/token", "application/x-www-form-urlencoded", bodies)
}

func TestBurstOfAppLoginsCannotExhaustThePool(t *testing.T) {
	tightPool(t)
	h := newHarness(t, true)
	bodies := make([]string, 8)
	for i := range bodies {
		a := h.app()
		name := fmt.Sprintf("ada%d", i)
		a.register(name)
		body := a.proofBody(identity.PurposeLogin)
		body["name"], body["password"] = name, testPassword
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		bodies[i] = string(encoded)
	}
	burst(t, h.url+"/v1/login", "application/json", bodies)
}

func TestRecoverTimingDoesNotRevealAccounts(t *testing.T) {
	h := newHarness(t, true)
	var names []string
	for i := range 3 {
		name := fmt.Sprintf("known%d", i)
		h.user(name, nil)
		names = append(names, name)
	}
	attempt := func(name string) time.Duration {
		start := time.Now()
		err := h.id.Recover(context.Background(), identity.Recovery{
			Name: name, Code: "aaaa-aaaa-aaaa-aaaa", NewPassword: "a-fresh-password-1", IP: "192.0.2." + name[len(name)-1:],
		})
		if !errors.Is(err, identity.ErrInvalidCredentials) {
			t.Fatalf("recover %s: %v", name, err)
		}
		return time.Since(start)
	}
	fastest := func(prefix []string) time.Duration {
		best := time.Hour
		for _, n := range prefix {
			best = min(best, attempt(n))
		}
		return best
	}
	known := fastest(names)
	unknown := fastest([]string{"missing0", "missing1", "missing2"})
	// A real Argon2 run takes far longer than the database work both paths share.
	if gap := max(known, unknown) - min(known, unknown); gap > 30*time.Millisecond {
		t.Errorf("known name took %v, unknown took %v", known, unknown)
	}
}

func TestLockoutStopsMFATokensAlreadyHeld(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	secret := b.enrollTOTP()
	_, first := h.app().tryLogin("ada", testPassword)
	_, second := h.app().tryLogin("ada", testPassword)
	for range 5 {
		h.do("POST", "/v1/login/mfa", "", map[string]string{"mfa_token": first["mfa_token"].(string), "code": "000000"})
	}
	status, body := h.do("POST", "/v1/login/mfa", "", map[string]string{"mfa_token": second["mfa_token"].(string), "code": totpAt(t, secret, 1)})
	h.wantStatus(status, body, http.StatusUnauthorized)
}

func TestSuccessfulMFAClearsFailures(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	secret := b.enrollTOTP()
	_, login := h.app().tryLogin("ada", testPassword)
	token := login["mfa_token"].(string)
	h.do("POST", "/v1/login/mfa", "", map[string]string{"mfa_token": token, "code": "000000"})
	status, body := h.do("POST", "/v1/login/mfa", "", map[string]string{"mfa_token": token, "code": totpAt(t, secret, 1)})
	h.wantStatus(status, body, http.StatusOK)
	var failed int
	if err := h.pool.QueryRow(context.Background(), "SELECT failed_count FROM auth.credentials").Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != 0 {
		t.Errorf("failed_count = %d after a good login", failed)
	}
}

func TestPlatformActionsNeedARecentSecondFactor(t *testing.T) {
	h := newHarness(t, false)
	h.tenant("ten_acme")
	root := h.user("root", map[string]string{"ten_acme": directory.RoleMember})
	h.platformAdmin(root)
	b := h.browser()
	b.signIn("root", testPassword, "")
	secret := b.enrollTOTP()
	b2 := h.browser()
	if st := b2.signIn("root", testPassword, totpAt(t, secret, 1)); st != http.StatusSeeOther {
		t.Fatalf("sign in: %d", st)
	}
	access, _ := h.redeem(b2)
	status, body := h.do("POST", "/v1/tenants", access, map[string]string{"id": "ten_new", "name": "New"})
	h.wantStatus(status, body, http.StatusCreated)

	if _, err := h.pool.Exec(context.Background(), "UPDATE auth.sessions SET mfa_at = now() - interval '16 minutes'"); err != nil {
		t.Fatal(err)
	}
	status, body = h.do("POST", "/v1/tenants", access, map[string]string{"id": "ten_late", "name": "Late"})
	h.wantStatus(status, body, http.StatusForbidden)
}

func TestAccountLimitIgnoresHowANameIsSpelled(t *testing.T) {
	h := newHarness(t, true)
	h.user("13800138000", nil)
	digits := "13800138000"
	var spellings []string
	for i := 1; i < len(digits); i++ {
		for j := i + 1; j < len(digits) && len(spellings) < 24; j++ {
			spellings = append(spellings, digits[:i]+" "+digits[i:j]+" "+digits[j:])
		}
	}
	limited := false
	for _, name := range spellings {
		_, _, err := h.id.VerifyCredentials(context.Background(), name, "wrong-password-1", "", "192.0.2."+fmt.Sprint(len(name)))
		if errors.Is(err, identity.ErrRateLimited) {
			limited = true
		}
	}
	if !limited {
		t.Error("respelling a phone number escaped the per-account limit")
	}
}

func TestHTTPSResponsesSetHSTS(t *testing.T) {
	for url, want := range map[string]bool{"https://auth.example": true, "http://localhost:8081": false} {
		rec := httptest.NewRecorder()
		New(Deps{PublicURL: url}).Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
		if got := rec.Header().Get("Strict-Transport-Security") != ""; got != want {
			t.Errorf("%s: HSTS set = %v", url, got)
		}
	}
}

func TestRequestsCarryADeadlineAndKeepTheirRouteInTheLog(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	var ok bool
	mux := http.NewServeMux()
	mux.HandleFunc("GET /probe", func(_ http.ResponseWriter, r *http.Request) {
		_, ok = r.Context().Deadline()
	})
	wrap(mux).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/probe", nil))
	if !ok {
		t.Error("no deadline on the request context")
	}
	if !strings.Contains(logs.String(), `route="GET /probe"`) {
		t.Errorf("route missing from log: %s", logs.String())
	}
}

func TestSuspendedUserCannotFinishMFALogin(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	secret := b.enrollTOTP()
	_, login := h.app().tryLogin("ada", testPassword)
	if _, err := h.pool.Exec(context.Background(), "UPDATE auth.users SET status = 'suspended'"); err != nil {
		t.Fatal(err)
	}
	status, body := h.do("POST", "/v1/login/mfa", "", map[string]string{"mfa_token": login["mfa_token"].(string), "code": totpAt(t, secret, 1)})
	h.wantStatus(status, body, http.StatusUnauthorized)
}

func TestApprovalFromARevokedDeviceCollectsNothing(t *testing.T) {
	h := newHarness(t, true)
	a := h.app()
	a.register("ada")
	b := h.browser()
	id, _ := b.startQR(t)
	a.claim(h.url + "/v1/qr/" + id)
	a.approve(id)
	if _, err := h.pool.Exec(context.Background(), "UPDATE auth.devices SET revoked_at = now()"); err != nil {
		t.Fatal(err)
	}
	if got := b.pollQR(t, ""); got != identity.QRExpired {
		t.Errorf("poll = %s", got)
	}
}

func TestPairingApprovalCannotBecomeABrowserSession(t *testing.T) {
	h := newHarness(t, true)
	phone := h.app()
	phone.register("ada")
	second := h.app()
	body := second.proofBody(identity.PurposePair)
	status, pair := h.do("POST", "/v1/login/pair", "", body)
	h.wantStatus(status, pair, http.StatusOK)
	id, _ := phone.claim(pair["qr_payload"].(string))
	phone.approve(id)

	b := h.browser()
	u, _ := url.Parse(h.url)
	b.client.Jar.SetCookies(u, []*http.Cookie{{Name: "t10_qr", Value: pair["poll_token"].(string), Path: "/"}})
	if got := b.pollQR(t, ""); got != identity.QRExpired {
		t.Errorf("browser poll of a pairing = %s", got)
	}
	status, out := h.do("POST", "/v1/login/pair/poll", "", map[string]string{"poll_token": pair["poll_token"].(string)})
	h.wantStatus(status, out, http.StatusOK)
	if out["status"] != "ok" {
		t.Errorf("pairing did not survive the browser poll: %v", out)
	}
}

func TestInvitedAppSignupToMFATenantKeepsItsRecoveryCodes(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	ctx := context.Background()
	if err := h.dir.SetRequireMFA(ctx, "test", "ten_acme", true); err != nil {
		t.Fatal(err)
	}
	invite, err := h.dir.CreateInvitation(ctx, "test", "ten_acme", directory.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	a := h.app()
	body := a.proofBody(identity.PurposeRegister)
	body["name"], body["password"], body["invite"] = "ada", testPassword, invite
	status, out := h.do("POST", "/v1/login/register", "", body)
	h.wantStatus(status, out, http.StatusOK)
	if codes, _ := out["recovery_codes"].([]any); len(codes) == 0 {
		t.Fatalf("no recovery codes: %v", out)
	}
	if out["tenant"] != "" {
		t.Errorf("tenant before a factor = %v", out["tenant"])
	}
	a.keep(out)

	status, out = h.do("POST", "/v1/me/totp/start", a.access, a.proof("totp_start"))
	h.wantStatus(status, out, http.StatusOK)
	code := totpAt(t, out["secret"].(string), 0)
	status, out = h.do("POST", "/v1/me/totp/confirm", a.access, map[string]string{"code": code})
	h.wantStatus(status, out, http.StatusOK)
	status, out = a.tryRefresh("")
	h.wantStatus(status, out, http.StatusOK)
	if out["tenant"] != "ten_acme" {
		t.Errorf("tenant after a factor = %v", out["tenant"])
	}
}

func TestInternalErrorsLogNoPath(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	writeInternal(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/qr/secret-id/claim", nil), errors.New("boom"))
	if strings.Contains(logs.String(), "secret-id") {
		t.Errorf("log holds the path: %s", logs.String())
	}
}

func TestAuthenticatorLinkSurvivesTheTemplate(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	_, _, body := b.post("/v1/account", url.Values{"action": {"totp_start"}, "password": {testPassword}})
	if !strings.Contains(body, `href="otpauth://`) {
		t.Errorf("authenticator link is missing: %s", body)
	}
}

func TestPasswordLengthCountsCharacters(t *testing.T) {
	h := newHarness(t, true)
	status, _, _ := h.browser().post("/v1/register", url.Values{"name": {"ada"}, "password": {"密码密码密码"}})
	if status != http.StatusBadRequest {
		t.Errorf("six-character password: %d", status)
	}
}

func TestTurningOffTOTPDropsTheSessionMFAFlag(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	secret := b.enrollTOTP()
	status, _, body := b.post("/v1/account", url.Values{"action": {"totp_disable"}, "password": {testPassword}, "code": {totpAt(t, secret, 1)}})
	if status != http.StatusOK {
		t.Fatalf("disable: %d %s", status, body)
	}
	var flagged int
	if err := h.pool.QueryRow(context.Background(), "SELECT count(*) FROM auth.sessions WHERE mfa_at IS NOT NULL").Scan(&flagged); err != nil {
		t.Fatal(err)
	}
	if flagged != 0 {
		t.Errorf("%d sessions still claim a second factor", flagged)
	}
}

func TestPasswordChangeSpendsOutstandingResetLinks(t *testing.T) {
	h := newHarness(t, true)
	userID := h.user("ada", nil)
	ctx := context.Background()
	first, err := h.id.IssueReset(ctx, "test", "platform", userID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.id.IssueReset(ctx, "test", "platform", userID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.id.ResetPassword(ctx, first, "a-fresh-password-1"); err != nil {
		t.Fatal(err)
	}
	if err := h.id.ResetPassword(ctx, second, "another-password-2"); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Errorf("older link: %v", err)
	}
}

func TestAccountWithNoNameCanStillStartTOTP(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	if err := h.id.ReleaseName(context.Background(), "test", "ada"); err != nil {
		t.Fatal(err)
	}
	status, _, body := b.post("/v1/account", url.Values{"action": {"totp_start"}, "password": {testPassword}})
	if status != http.StatusOK {
		t.Errorf("totp_start: %d %s", status, body)
	}
}
