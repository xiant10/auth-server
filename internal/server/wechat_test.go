package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/identity"
)

const testWeChatClient = "t10-miniprogram-test"

// fakeWeChat answers codes of the form "<openid>" and refuses "bad".
type fakeWeChat struct{ calls int }

func (f *fakeWeChat) OpenID(_ context.Context, code string) (string, error) {
	f.calls++
	if code == "bad" {
		return "", identity.ErrWeChatCode
	}
	return code, nil
}

func wechatHarness(t *testing.T) (*harness, *fakeWeChat) {
	h := newHarness(t, false)
	fake := &fakeWeChat{}
	h.id.UseWeChat(fake, "wx-test")
	h.tenant("ten_acme")
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	h.user("ben", map[string]string{"ten_acme": directory.RoleMember})
	return h, fake
}

func wechatSignIn(h *harness, name, password, code string) (int, map[string]any) {
	h.t.Helper()
	return h.do("POST", "/v1/wechat/signin", "", map[string]any{"client_id": testWeChatClient, "code": code, "name": name, "password": password, "tenant": "ten_acme"})
}

func wechatRefresh(h *harness, session, code string) (int, map[string]any) {
	h.t.Helper()
	return h.do("POST", "/v1/wechat/refresh", "", map[string]any{"client_id": testWeChatClient, "session_id": session, "code": code})
}

func TestWeChatSignIn(t *testing.T) {
	h, fake := wechatHarness(t)

	// A wrong password spends no WeChat code and binds nothing.
	if status, _ := wechatSignIn(h, "ada", "wrong", "wx-ada"); status != http.StatusUnauthorized {
		t.Errorf("wrong password = %d", status)
	}
	if fake.calls != 0 {
		t.Errorf("a wrong password called WeChat %d times", fake.calls)
	}
	if status, out := wechatSignIn(h, "ada", testPassword, "bad"); status != http.StatusBadRequest || out["error"] != "wechat_code" {
		t.Errorf("refused code = %d %v", status, out)
	}

	status, out := wechatSignIn(h, "ada", testPassword, "wx-ada")
	h.wantStatus(status, out, http.StatusOK)
	session := out["session_id"].(string)
	if out["tenant"] != "ten_acme" || out["access_token"] == "" {
		t.Errorf("sign-in = %v", out)
	}

	// One identity to one account, in both directions.
	if status, out := wechatSignIn(h, "ben", testPassword, "wx-ada"); status != http.StatusConflict || out["error"] != "wechat_bound" {
		t.Errorf("a second account on this WeChat = %d %v", status, out)
	}
	if status, out := wechatSignIn(h, "ada", testPassword, "wx-other"); status != http.StatusConflict {
		t.Errorf("a second WeChat for this account = %d %v", status, out)
	}

	// Only that WeChat identity can refresh, and a session ID alone is nothing.
	status, out = wechatRefresh(h, session, "wx-ada")
	h.wantStatus(status, out, http.StatusOK)
	if out["access_token"] == "" || out["session_id"] != session {
		t.Errorf("refresh = %v", out)
	}
	if status, _ := wechatRefresh(h, session, "wx-other"); status != http.StatusBadRequest {
		t.Errorf("another WeChat refreshed: %d", status)
	}
	if status, _ := wechatRefresh(h, "ses_nothing", "wx-ada"); status != http.StatusBadRequest {
		t.Errorf("an unknown session refreshed: %d", status)
	}

	// Going idle comes back to the password, with the binding kept.
	ctx := context.Background()
	if _, err := h.pool.Exec(ctx, "UPDATE auth.sessions SET idle_expires_at = now() - interval '1 minute' WHERE id = $1", session); err != nil {
		t.Fatal(err)
	}
	if status, _ := wechatRefresh(h, session, "wx-ada"); status != http.StatusBadRequest {
		t.Errorf("an idle session refreshed: %d", status)
	}
	status, out = wechatSignIn(h, "ada", testPassword, "wx-ada")
	h.wantStatus(status, out, http.StatusOK)
	session = out["session_id"].(string)

	// Signing out ends the session, and needs the WeChat identity too.
	if status, _ := h.do("POST", "/v1/wechat/signout", "", map[string]any{"client_id": testWeChatClient, "session_id": session, "code": "wx-other"}); status != http.StatusBadRequest {
		t.Errorf("another WeChat signed out: %d", status)
	}
	if status, _ := h.do("POST", "/v1/wechat/signout", "", map[string]any{"client_id": testWeChatClient, "session_id": session, "code": "wx-ada"}); status != http.StatusNoContent {
		t.Errorf("sign-out = %d", status)
	}
	if status, _ := wechatRefresh(h, session, "wx-ada"); status != http.StatusBadRequest {
		t.Errorf("a signed-out session refreshed: %d", status)
	}

	// A disabled account stops at once, and so does a removed binding.
	status, out = wechatSignIn(h, "ada", testPassword, "wx-ada")
	h.wantStatus(status, out, http.StatusOK)
	session = out["session_id"].(string)
	if _, err := h.pool.Exec(ctx, "UPDATE auth.wechat_bindings SET removed_at = now() WHERE openid = 'wx-ada'"); err != nil {
		t.Fatal(err)
	}
	if status, _ := wechatRefresh(h, session, "wx-ada"); status != http.StatusBadRequest {
		t.Errorf("a removed binding refreshed: %d", status)
	}
	status, out = wechatSignIn(h, "ben", testPassword, "wx-ben")
	h.wantStatus(status, out, http.StatusOK)
	if _, err := h.pool.Exec(ctx, "UPDATE auth.users SET status = 'suspended' WHERE id = (SELECT user_id FROM auth.wechat_bindings WHERE openid = 'wx-ben' AND removed_at IS NULL)"); err != nil {
		t.Fatal(err)
	}
	if status, _ := wechatRefresh(h, out["session_id"].(string), "wx-ben"); status != http.StatusBadRequest {
		t.Errorf("a disabled account refreshed: %d", status)
	}
}

func TestWeChatRoutesNeedAWeChatClient(t *testing.T) {
	h, _ := wechatHarness(t)
	status, _ := h.do("POST", "/v1/wechat/signin", "", map[string]any{"client_id": testMobileClient, "code": "wx", "name": "ada", "password": testPassword})
	if status == http.StatusOK {
		t.Error("the mobile client signed in through WeChat")
	}
}

// WeChat's URL holds the app secret, so no failure may repeat it.
func TestWeChatAPIKeepsTheSecretOutOfErrors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("js_code") == "good" {
			_, _ = w.Write([]byte(`{"openid":"o1"}`))
			return
		}
		_, _ = w.Write([]byte(`{"errcode":40029}`))
	}))
	api := identity.WeChatAPI{AppID: "wx", Secret: "the-secret", BaseURL: ts.URL, HTTP: &http.Client{Timeout: time.Second}}
	if got, err := api.OpenID(context.Background(), "good"); err != nil || got != "o1" {
		t.Errorf("good code = %q %v", got, err)
	}
	if _, err := api.OpenID(context.Background(), "bad"); err == nil {
		t.Error("a refused code passed")
	}
	ts.Close()
	_, err := api.OpenID(context.Background(), "good")
	if err == nil || strings.Contains(err.Error(), "the-secret") {
		t.Errorf("an outage said: %v", err)
	}
}
