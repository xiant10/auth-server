package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/identity"
)

// app plays the mobile app: two P-256 keys, DER signatures, base64url text.
type app struct {
	h                 *harness
	approval, session *ecdsa.PrivateKey
	access, sessionID string
	deviceID, tenant  string
}

func (h *harness) app() *app {
	h.t.Helper()
	approval, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	session, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	return &app{h: h, approval: approval, session: session}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func point(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	p, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func spki(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// device reports the session key as SPKI and the approval key as a raw point,
// covering both encodings the platforms produce.
func (a *app) device() map[string]string {
	return map[string]string{
		"name": "Ada's phone", "platform": "ios",
		"approval_public_key": b64(point(a.h.t, a.approval)),
		"session_public_key":  b64(spki(a.h.t, a.session)),
	}
}

func (a *app) sign(key *ecdsa.PrivateKey, purpose, challenge, binding string) string {
	a.h.t.Helper()
	digest := sha256.Sum256(identity.SignedMessage(purpose, challenge, binding))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		a.h.t.Fatal(err)
	}
	return b64(sig)
}

func (a *app) challenge(purpose string) string {
	a.h.t.Helper()
	status, body := a.h.do("POST", "/v1/challenges", "", map[string]string{"purpose": purpose})
	a.h.wantStatus(status, body, http.StatusOK)
	return body["challenge"].(string)
}

func (a *app) proofBody(purpose string) map[string]any {
	a.h.t.Helper()
	c := a.challenge(purpose)
	return map[string]any{
		"client_id": testMobileClient, "device": a.device(), "challenge": c,
		"signature": a.sign(a.session, purpose, c, identity.KeyBinding(point(a.h.t, a.session))),
	}
}

func (a *app) keep(body map[string]any) {
	a.access = body["access_token"].(string)
	a.sessionID = body["session_id"].(string)
	a.deviceID = body["device_id"].(string)
	a.tenant = body["tenant"].(string)
}

func (a *app) tryLogin(name, password string) (int, map[string]any) {
	a.h.t.Helper()
	body := a.proofBody(identity.PurposeLogin)
	body["name"], body["password"] = name, password
	return a.h.do("POST", "/v1/login", "", body)
}

func (a *app) login(name string) {
	a.h.t.Helper()
	status, body := a.tryLogin(name, testPassword)
	a.h.wantStatus(status, body, http.StatusOK)
	if body["status"] != "ok" {
		a.h.t.Fatalf("login: %v", body)
	}
	a.keep(body)
}

func (a *app) register(name string) []string {
	a.h.t.Helper()
	body := a.proofBody(identity.PurposeRegister)
	body["name"], body["password"] = name, testPassword
	status, out := a.h.do("POST", "/v1/login/register", "", body)
	a.h.wantStatus(status, out, http.StatusOK)
	a.keep(out)
	var codes []string
	for _, c := range out["recovery_codes"].([]any) {
		codes = append(codes, c.(string))
	}
	return codes
}

func (a *app) tryRefresh(tenant string) (int, map[string]any) {
	a.h.t.Helper()
	c := a.challenge(identity.PurposeRefresh)
	return a.h.token(url.Values{
		"grant_type": {"device_refresh"}, "client_id": {testMobileClient}, "session_id": {a.sessionID},
		"challenge": {c}, "signature": {a.sign(a.session, identity.PurposeRefresh, c, a.sessionID)}, "tenant": {tenant},
	})
}

func (a *app) proof(action string) map[string]any {
	a.h.t.Helper()
	c := a.challenge(identity.PurposeReauth)
	return map[string]any{"challenge": c, "signature": a.sign(a.approval, identity.PurposeReauth, c, a.deviceID+"\n"+action)}
}

func (a *app) claim(payload string) (string, map[string]any) {
	a.h.t.Helper()
	id := payload[strings.LastIndex(payload, "/")+1:]
	status, body := a.h.do("POST", "/v1/qr/"+id+"/claim", a.access, nil)
	a.h.wantStatus(status, body, http.StatusOK)
	return id, body
}

func (a *app) approve(id string) {
	a.h.t.Helper()
	c := a.challenge(identity.PurposeApprove)
	status, body := a.h.do("POST", "/v1/qr/"+id+"/approve", a.access, map[string]string{
		"challenge": c, "signature": a.sign(a.approval, identity.PurposeApprove, c, id),
	})
	a.h.wantStatus(status, body, http.StatusOK)
}

func TestLoginEnrollsDeviceAndTokenWorks(t *testing.T) {
	h := newHarness(t, false)
	h.tenant("ten_acme")
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	a := h.app()
	a.login("ada")

	if a.tenant != "ten_acme" || a.deviceID == "" {
		t.Errorf("login = %+v", a)
	}
	status, body := h.do("POST", "/v1/rooms/admission", a.access, map[string]string{"room": "r"})
	h.wantStatus(status, body, http.StatusOK)

	status, body = h.do("GET", "/v1/me", a.access, nil)
	h.wantStatus(status, body, http.StatusOK)
	devices := body["devices"].([]any)
	if len(devices) != 1 || devices[0].(map[string]any)["current"] != true {
		t.Errorf("devices = %v", devices)
	}
	if body["active_tenant"] != "ten_acme" || len(body["tenants"].([]any)) != 1 {
		t.Errorf("me = %v", body)
	}
}

func TestLoginRefusals(t *testing.T) {
	h := newHarness(t, false)
	h.tenant("ten_acme")
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	a := h.app()

	// Only a direct-login client may take a password.
	body := a.proofBody(identity.PurposeLogin)
	body["client_id"], body["name"], body["password"] = testClientID, "ada", testPassword
	status, out := h.do("POST", "/v1/login", "", body)
	h.wantStatus(status, out, http.StatusUnauthorized)

	// A signature by someone else's key.
	body = a.proofBody(identity.PurposeLogin)
	body["name"], body["password"] = "ada", testPassword
	body["signature"] = a.sign(a.approval, identity.PurposeLogin, body["challenge"].(string), "x")
	status, out = h.do("POST", "/v1/login", "", body)
	h.wantStatus(status, out, http.StatusBadRequest)
	if out["error"] != "invalid_device" {
		t.Errorf("error = %v", out["error"])
	}

	// A challenge works once, and only for its purpose.
	body = a.proofBody(identity.PurposeLogin)
	body["name"], body["password"] = "ada", "wrong-password"
	status, out = h.do("POST", "/v1/login", "", body)
	h.wantStatus(status, out, http.StatusUnauthorized)
	status, out = h.do("POST", "/v1/login", "", body)
	h.wantStatus(status, out, http.StatusBadRequest)
	if out["error"] != "invalid_challenge" {
		t.Errorf("error = %v", out["error"])
	}
	c := a.challenge(identity.PurposeRefresh)
	body = a.proofBody(identity.PurposeLogin)
	body["name"], body["password"], body["challenge"] = "ada", testPassword, c
	body["signature"] = a.sign(a.session, identity.PurposeLogin, c, identity.KeyBinding(point(t, a.session)))
	status, out = h.do("POST", "/v1/login", "", body)
	h.wantStatus(status, out, http.StatusBadRequest)

	// A mistyped field fails instead of being ignored.
	status, out = h.do("POST", "/v1/challenges", "", map[string]string{"purpose": "login", "typo": "x"})
	h.wantStatus(status, out, http.StatusBadRequest)
}

func TestLoginWithTOTP(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	secret := b.enrollTOTP()
	a := h.app()

	status, body := a.tryLogin("ada", testPassword)
	h.wantStatus(status, body, http.StatusOK)
	if body["status"] != "mfa_required" {
		t.Fatalf("login = %v", body)
	}
	token := body["mfa_token"].(string)

	status, out := h.do("POST", "/v1/login/mfa", "", map[string]string{"mfa_token": token, "code": "000000"})
	h.wantStatus(status, out, http.StatusUnauthorized)
	status, out = h.do("POST", "/v1/login/mfa", "", map[string]string{"mfa_token": token, "code": totpAt(t, secret, 1)})
	h.wantStatus(status, out, http.StatusOK)
	a.keep(out)

	// The token is spent, and a device enrolled with a factor counts as one.
	status, out = h.do("POST", "/v1/login/mfa", "", map[string]string{"mfa_token": token, "code": totpAt(t, secret, 1)})
	h.wantStatus(status, out, http.StatusBadRequest)
	var capable bool
	if err := h.pool.QueryRow(context.Background(), "SELECT mfa_capable FROM auth.devices").Scan(&capable); err != nil {
		t.Fatal(err)
	}
	if !capable {
		t.Error("device enrolled with TOTP is not MFA capable")
	}
}

func TestMFATokenAttemptsAreLimited(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	secret := b.enrollTOTP()
	_, body := h.app().tryLogin("ada", testPassword)
	token := body["mfa_token"].(string)
	for range 5 {
		h.do("POST", "/v1/login/mfa", "", map[string]string{"mfa_token": token, "code": "000000"})
	}
	status, out := h.do("POST", "/v1/login/mfa", "", map[string]string{"mfa_token": token, "code": totpAt(t, secret, 1)})
	h.wantStatus(status, out, http.StatusBadRequest)
}

func TestSecondDeviceNeedsApproval(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	first := h.app()
	first.login("ada")

	// The same keys come straight back, as after a password reset.
	first.login("ada")

	// New keys and a password alone are not enough.
	second := h.app()
	status, body := second.tryLogin("ada", testPassword)
	h.wantStatus(status, body, http.StatusForbidden)
	if body["error"] != "device_approval_required" {
		t.Fatalf("error = %v", body["error"])
	}

	req := second.proofBody(identity.PurposePair)
	status, pair := h.do("POST", "/v1/login/pair", "", req)
	h.wantStatus(status, pair, http.StatusOK)
	poll := map[string]string{"poll_token": pair["poll_token"].(string)}

	status, body = h.do("POST", "/v1/login/pair/poll", "", poll)
	h.wantStatus(status, body, http.StatusOK)
	if body["status"] != "pending" {
		t.Fatalf("poll = %v", body)
	}

	id, request := first.claim(pair["qr_payload"].(string))
	if request["kind"] != "device" || request["device_name"] != "Ada's phone" {
		t.Errorf("request = %v", request)
	}
	first.approve(id)

	status, body = h.do("POST", "/v1/login/pair/poll", "", poll)
	h.wantStatus(status, body, http.StatusOK)
	second.keep(body)
	status, body = second.tryRefresh("")
	h.wantStatus(status, body, http.StatusOK)

	// An approval yields one enrollment.
	status, body = h.do("POST", "/v1/login/pair/poll", "", poll)
	h.wantStatus(status, body, http.StatusOK)
	if body["status"] != "expired" {
		t.Errorf("second poll = %v", body)
	}
}

func TestPasswordOnlyDeviceCannotSatisfyMFA(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.user("boss", map[string]string{"ten_acme": directory.RoleAdmin})
	a := h.app()
	a.login("boss")
	if err := h.dir.SetRequireMFA(context.Background(), "test", "ten_acme", true); err != nil {
		t.Fatal(err)
	}

	// Someone with only the password enrolled this device, so it proves nothing.
	status, body := a.tryRefresh("")
	h.wantStatus(status, body, http.StatusForbidden)

	// Nor does a browser sign-in it approves.
	b := h.browser()
	id, poll := b.startQR(t)
	a.claim(id)
	a.approve(id)
	if got := b.pollQR(t, poll); got != identity.QRApproved {
		t.Fatalf("poll = %s", got)
	}
	status, out := h.token(redeem(b.code()))
	h.wantStatus(status, out, http.StatusForbidden)
	if out["error"] != "mfa_required" {
		t.Errorf("error = %v", out["error"])
	}
}

func TestDeviceRefresh(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	userID := h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	a := h.app()
	a.login("ada")

	// A lost response costs nothing: the next refresh just works.
	for range 3 {
		status, body := a.tryRefresh("")
		h.wantStatus(status, body, http.StatusOK)
	}

	// The approval key must not work here, and a signature is single use.
	c := a.challenge(identity.PurposeRefresh)
	form := url.Values{
		"grant_type": {"device_refresh"}, "client_id": {testMobileClient}, "session_id": {a.sessionID},
		"challenge": {c}, "signature": {a.sign(a.approval, identity.PurposeRefresh, c, a.sessionID)},
	}
	status, body := h.token(form)
	h.wantStatus(status, body, http.StatusBadRequest)

	// The mobile idle limit moves forward, with no absolute limit.
	var absolute *time.Time
	var idle time.Time
	if err := h.pool.QueryRow(context.Background(),
		"SELECT idle_expires_at, absolute_expires_at FROM auth.sessions WHERE id = $1", a.sessionID).Scan(&idle, &absolute); err != nil {
		t.Fatal(err)
	}
	if absolute != nil || time.Until(idle) < 80*24*time.Hour {
		t.Errorf("idle = %v, absolute = %v", idle, absolute)
	}

	inactive := directory.MemberInactive
	if _, err := h.dir.UpdateMember(context.Background(), "test", "ten_acme", userID, directory.MemberUpdate{Status: &inactive}); err != nil {
		t.Fatal(err)
	}
	status, body = a.tryRefresh("")
	h.wantStatus(status, body, http.StatusForbidden)
}

func TestSeveralTenantsPickedByRefresh(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.tenant("ten_other")
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember, "ten_other": directory.RoleAdmin})
	a := h.app()
	a.login("ada")
	if a.tenant != "" {
		t.Fatalf("tenant = %q", a.tenant)
	}

	// With no tenant chosen, nothing tenant-scoped opens.
	status, body := h.do("POST", "/v1/rooms/admission", a.access, map[string]string{"room": "r"})
	h.wantStatus(status, body, http.StatusForbidden)

	status, body = h.do("GET", "/v1/me", a.access, nil)
	h.wantStatus(status, body, http.StatusOK)
	if len(body["tenants"].([]any)) != 2 {
		t.Fatalf("tenants = %v", body["tenants"])
	}

	status, body = a.tryRefresh("ten_other")
	h.wantStatus(status, body, http.StatusOK)
	a.keep(body)
	status, body = h.do("POST", "/v1/rooms/admission", a.access, map[string]string{"room": "r"})
	h.wantStatus(status, body, http.StatusOK)
	if body["room_name"] != "ten_other__r" {
		t.Errorf("room_name = %v", body["room_name"])
	}

	// The choice sticks, and a tenant outside the memberships is refused.
	status, body = a.tryRefresh("")
	h.wantStatus(status, body, http.StatusOK)
	if body["tenant"] != "ten_other" {
		t.Errorf("tenant = %v", body["tenant"])
	}
	status, body = a.tryRefresh("ten_nope")
	h.wantStatus(status, body, http.StatusForbidden)
}

func TestInAppRegistration(t *testing.T) {
	t.Run("open in dev", func(t *testing.T) {
		h := newHarness(t, true)
		a := h.app()
		if codes := a.register("ada"); len(codes) != 10 {
			t.Fatalf("codes = %d", len(codes))
		}
		status, body := h.do("POST", "/v1/rooms/admission", a.access, map[string]string{"room": "r"})
		h.wantStatus(status, body, http.StatusOK)

		dup := h.app()
		req := dup.proofBody(identity.PurposeRegister)
		req["name"], req["password"] = "ADA", testPassword
		status, body = h.do("POST", "/v1/login/register", "", req)
		h.wantStatus(status, body, http.StatusConflict)
		if body["error"] != "name_taken" {
			t.Errorf("error = %v", body["error"])
		}
	})

	t.Run("closed otherwise", func(t *testing.T) {
		h := newHarness(t, false)
		h.tenant("ten_acme")
		a := h.app()
		req := a.proofBody(identity.PurposeRegister)
		req["name"], req["password"] = "ada", testPassword
		status, body := h.do("POST", "/v1/login/register", "", req)
		h.wantStatus(status, body, http.StatusForbidden)
		if body["error"] != "registration_closed" {
			t.Errorf("error = %v", body["error"])
		}

		invite, err := h.dir.CreateInvitation(context.Background(), "test", "ten_acme", directory.RoleMember)
		if err != nil {
			t.Fatal(err)
		}
		req = a.proofBody(identity.PurposeRegister)
		req["name"], req["password"], req["invite"] = "ada", testPassword, invite
		status, body = h.do("POST", "/v1/login/register", "", req)
		h.wantStatus(status, body, http.StatusOK)
		if body["tenant"] != "ten_acme" {
			t.Errorf("tenant = %v", body["tenant"])
		}
	})
}

func TestInAppRecoveryThenSignBackIn(t *testing.T) {
	h := newHarness(t, true)
	a := h.app()
	codes := a.register("ada")

	const newPassword = "a-brand-new-long-password"
	status, body := h.do("POST", "/v1/login/recover", "", map[string]string{
		"name": "ada", "recovery_code": codes[0], "new_password": newPassword,
	})
	h.wantStatus(status, body, http.StatusOK)

	// The session ended, but the device stays enrolled, so its keys need no approval.
	status, body = a.tryRefresh("")
	h.wantStatus(status, body, http.StatusBadRequest)
	status, body = a.tryLogin("ada", newPassword)
	h.wantStatus(status, body, http.StatusOK)
}

func TestBiometricCredentialChanges(t *testing.T) {
	h := newHarness(t, true)
	a := h.app()
	a.register("ada")

	// App reset: a fresh biometric replaces the current password.
	const newPassword = "a-brand-new-long-password"
	req := a.proof("password")
	req["new_password"] = newPassword
	status, body := h.do("POST", "/v1/me/password", a.access, req)
	h.wantStatus(status, body, http.StatusOK)
	if st := h.browser().signIn("ada", newPassword, ""); st != http.StatusSeeOther {
		t.Errorf("new password: %d", st)
	}

	// A proof covers one action.
	req = a.proof("name_add")
	req["new_password"] = "another-long-new-password"
	status, body = h.do("POST", "/v1/me/password", a.access, req)
	h.wantStatus(status, body, http.StatusBadRequest)

	// The silent session key must not pass as a biometric check.
	c := a.challenge(identity.PurposeReauth)
	status, body = h.do("POST", "/v1/me/password", a.access, map[string]string{
		"challenge": c, "signature": a.sign(a.session, identity.PurposeReauth, c, a.deviceID+"\npassword"),
		"new_password": "another-long-new-password",
	})
	h.wantStatus(status, body, http.StatusBadRequest)

	req = a.proof("name_add")
	req["name"] = "+8613800138000"
	status, body = h.do("POST", "/v1/me/names", a.access, req)
	h.wantStatus(status, body, http.StatusOK)

	req = a.proof("totp_start")
	status, body = h.do("POST", "/v1/me/totp/start", a.access, req)
	h.wantStatus(status, body, http.StatusOK)
	secret := body["secret"].(string)
	status, body = h.do("POST", "/v1/me/totp/confirm", a.access, map[string]string{"code": totpAt(t, secret, 0)})
	h.wantStatus(status, body, http.StatusOK)

	status, body = h.do("POST", "/v1/me/recovery-codes", a.access, a.proof("recovery_codes"))
	h.wantStatus(status, body, http.StatusOK)
	if len(body["recovery_codes"].([]any)) != 10 {
		t.Errorf("codes = %v", body)
	}

	status, body = h.do("POST", "/v1/me/totp/disable", a.access, a.proof("totp_disable"))
	h.wantStatus(status, body, http.StatusOK)
}

func TestBrowserSessionsCannotUseDeviceRoutes(t *testing.T) {
	h := newHarness(t, true)
	b := h.browser()
	b.register("ada", "")
	access, _ := h.redeem(b)
	status, body := h.do("POST", "/v1/me/signout-all", access, nil)
	h.wantStatus(status, body, http.StatusForbidden)
}

func TestInAppInvitation(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_other")
	a := h.app()
	a.register("ada")
	invite, err := h.dir.CreateInvitation(context.Background(), "test", "ten_other", directory.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	status, body := h.do("POST", "/v1/me/invitations/accept", a.access, map[string]string{"invite": invite})
	h.wantStatus(status, body, http.StatusOK)
	if body["tenant"] != "ten_other" {
		t.Errorf("tenant = %v", body["tenant"])
	}
}

// startQR opens a QR request and returns its ID and the browser's result poll.
func (b *browser) startQR(t *testing.T) (string, string) {
	t.Helper()
	req, err := http.NewRequest("POST", b.h.url+"/v1/signin/qr", strings.NewReader(`{"next":"`+authorizePath("st")+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", b.h.url)
	req.Header.Set("User-Agent", "Test Browser")
	resp, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	status, _, body := readPage(t, resp)
	if status != http.StatusOK || !strings.Contains(body, "data:image/png;base64,") {
		t.Fatalf("qr: %d %s", status, body)
	}
	// The ID reaches a real app through the camera; here it comes from the row
	// a test-only ticket mints, since the PNG is not decoded.
	ticket, err := b.h.id.StartQRLogin(context.Background(), testClientID, "198.51.100.7", "Test Browser")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(b.h.url)
	b.client.Jar.SetCookies(u, []*http.Cookie{{Name: "t10_qr", Value: ticket.Poll, Path: "/"}})
	return ticket.ID, ticket.Poll
}

func (b *browser) pollQR(t *testing.T, _ string) string {
	t.Helper()
	req, err := http.NewRequest("POST", b.h.url+"/v1/signin/qr/poll", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", b.h.url)
	resp, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	status, _, body := readPage(t, resp)
	if status != http.StatusOK {
		t.Fatalf("poll: %d %s", status, body)
	}
	for _, s := range []string{identity.QRApproved, identity.QRDenied, identity.QRExpired, identity.QRClaimed, identity.QRPending} {
		if strings.Contains(body, `"`+s+`"`) {
			return s
		}
	}
	t.Fatalf("poll = %s", body)
	return ""
}

func TestQRSignIn(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	a := h.app()
	a.login("ada")

	b := h.browser()
	id, poll := b.startQR(t)
	if got := b.pollQR(t, poll); got != identity.QRPending {
		t.Fatalf("poll = %s", got)
	}

	// The app gets what it needs to show the user.
	_, request := a.claim(id)
	if request["client_id"] != testClientID {
		t.Errorf("client = %v", request)
	}
	if request["requester_ip"] != "198.51.100.7" || request["user_agent"] != "Test Browser" {
		t.Errorf("request = %v", request)
	}
	if got := b.pollQR(t, poll); got != identity.QRClaimed {
		t.Fatalf("poll = %s", got)
	}

	// A code cannot be claimed twice, even by the same user's other device.
	status, body := h.do("POST", "/v1/qr/"+id+"/claim", a.access, nil)
	h.wantStatus(status, body, http.StatusBadRequest)

	a.approve(id)
	if got := b.pollQR(t, poll); got != identity.QRApproved {
		t.Fatalf("poll = %s", got)
	}

	// The browser is now signed in, and the normal code flow finishes.
	status, out := h.token(redeem(b.code()))
	h.wantStatus(status, out, http.StatusOK)
	st, body := h.do("POST", "/v1/rooms/admission", out["access_token"].(string), map[string]string{"room": "r"})
	h.wantStatus(st, body, http.StatusOK)
}

func TestQRRefusals(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	h.user("eve", map[string]string{"ten_acme": directory.RoleMember})
	a, eve := h.app(), h.app()
	a.login("ada")
	eve.login("eve")

	// A browser token is no authenticator.
	b := h.browser()
	id, poll := b.startQR(t)
	status, body := h.do("POST", "/v1/qr/"+id+"/claim", h.login("ada", ""), nil)
	h.wantStatus(status, body, http.StatusForbidden)

	// Only the device that claimed can approve, and only with the approval key.
	a.claim(id)
	c := eve.challenge(identity.PurposeApprove)
	status, body = h.do("POST", "/v1/qr/"+id+"/approve", eve.access, map[string]string{
		"challenge": c, "signature": eve.sign(eve.approval, identity.PurposeApprove, c, id),
	})
	h.wantStatus(status, body, http.StatusBadRequest)
	c = a.challenge(identity.PurposeApprove)
	status, body = h.do("POST", "/v1/qr/"+id+"/approve", a.access, map[string]string{
		"challenge": c, "signature": a.sign(a.session, identity.PurposeApprove, c, id),
	})
	h.wantStatus(status, body, http.StatusBadRequest)

	// A signature for another request does not carry over.
	c = a.challenge(identity.PurposeApprove)
	status, body = h.do("POST", "/v1/qr/"+id+"/approve", a.access, map[string]string{
		"challenge": c, "signature": a.sign(a.approval, identity.PurposeApprove, c, "other-id"),
	})
	h.wantStatus(status, body, http.StatusBadRequest)

	// Denied means denied.
	status, body = h.do("POST", "/v1/qr/"+id+"/deny", a.access, nil)
	h.wantStatus(status, body, http.StatusOK)
	if got := b.pollQR(t, poll); got != identity.QRDenied {
		t.Errorf("poll = %s", got)
	}
	if st, _, _ := b.get("/v1/account"); st != http.StatusSeeOther {
		t.Errorf("denied browser signed in: %d", st)
	}

	// Expiry.
	b2 := h.browser()
	id2, poll2 := b2.startQR(t)
	if _, err := h.pool.Exec(context.Background(), "UPDATE auth.qr_logins SET expires_at = now() - interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	status, body = h.do("POST", "/v1/qr/"+id2+"/claim", a.access, nil)
	h.wantStatus(status, body, http.StatusBadRequest)
	if got := b2.pollQR(t, poll2); got != identity.QRExpired {
		t.Errorf("poll = %s", got)
	}
}

func TestLostPhone(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	a := h.app()
	a.login("ada")

	// From a browser, with the password, the user removes the lost device.
	b := h.browser()
	b.signIn("ada", testPassword, "")
	form := url.Values{"action": {"device_revoke"}, "device_id": {a.deviceID}, "password": {testPassword}}
	if status, _, body := b.post("/v1/account", form); status != http.StatusOK {
		t.Fatalf("revoke: %d %s", status, body)
	}

	// Its token, session and approval rights end at once.
	status, body := h.do("GET", "/v1/me", a.access, nil)
	h.wantStatus(status, body, http.StatusUnauthorized)
	status, body = a.tryRefresh("")
	h.wantStatus(status, body, http.StatusBadRequest)

	// Those keys are dead for good, and a new phone needs no approval now.
	status, body = a.tryLogin("ada", testPassword)
	h.wantStatus(status, body, http.StatusForbidden)
	if body["error"] != "device_revoked" {
		t.Errorf("error = %v", body["error"])
	}
	h.app().login("ada")
}

func TestDeviceKeyCannotMoveBetweenAccounts(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	h.user("eve", map[string]string{"ten_acme": directory.RoleMember})
	a := h.app()
	a.login("ada")
	status, body := a.tryLogin("eve", testPassword)
	h.wantStatus(status, body, http.StatusBadRequest)
}

// TestOpenAPICoversTheMobileAPI keeps the published contract honest: every
// route the app calls, and every error code it can see, must be in the spec.
func TestOpenAPICoversTheMobileAPI(t *testing.T) {
	data, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths      map[string]map[string]any `yaml:"paths"`
		Components struct {
			Schemas struct {
				ErrorCode struct {
					Enum []string `yaml:"enum"`
				} `yaml:"ErrorCode"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}

	for _, rt := range New(Deps{}).routes() {
		mobile := rt.access == accessDevice ||
			strings.HasPrefix(rt.pattern, "/v1/login") || rt.pattern == "/v1/challenges" ||
			rt.pattern == "/v1/me" || rt.pattern == "/v1/logout" || rt.pattern == "/v1/token"
		if !mobile {
			continue
		}
		if _, ok := spec.Paths[rt.pattern][strings.ToLower(rt.method)]; !ok {
			t.Errorf("%s %s is not in docs/openapi.yaml", rt.method, rt.pattern)
		}
	}

	source, err := os.ReadFile("mobile.go")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for _, code := range spec.Components.Schemas.ErrorCode.Enum {
		documented[code] = true
	}
	for _, m := range regexp.MustCompile(`http\.Status\w+, "([a-z_]+)"`).FindAllStringSubmatch(string(source), -1) {
		if !documented[m[1]] {
			t.Errorf("error code %q is not in docs/openapi.yaml", m[1])
		}
	}
}

// Revoking a device also revokes its sessions, so this checks the device test
// by itself, in case a session ever outlives its device.
func TestRevokedDeviceStopsItsSessionOnItsOwn(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	a := h.app()
	a.login("ada")
	if _, err := h.pool.Exec(context.Background(), "UPDATE auth.devices SET revoked_at = now()"); err != nil {
		t.Fatal(err)
	}
	status, body := h.do("GET", "/v1/me", a.access, nil)
	h.wantStatus(status, body, http.StatusUnauthorized)
	status, body = a.tryRefresh("")
	h.wantStatus(status, body, http.StatusBadRequest)
}
