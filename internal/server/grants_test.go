package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"t10-auth-server/internal/agents"
	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/identity"
)

const (
	voiceRuntime  = "t10-livekit-agent"
	piRuntime     = "agent-pi"
	firingRuntime = agents.StandingRuntime
	gatedRuntime  = "agent-gated"
	toolGateway   = "ai-gateway-tools"
	listedService = "crm-mcp"
	otherService  = "deals"
)

var testRuntimes = []agents.Runtime{
	{Name: voiceRuntime, Voice: true, Actions: []string{"agent:use"}, Audiences: []string{piRuntime}},
	{Name: piRuntime, Actions: []string{"agent:use", "crm:read"}, Audiences: []string{piRuntime, listedService}},
	{Name: gatedRuntime, ToolAudience: toolGateway, Actions: []string{"agent:use", "crm:read"}, Audiences: []string{gatedRuntime, listedService, toolGateway}},
	{Name: firingRuntime, Optional: true, Actions: []string{"agent:use", "crm:read"}, Audiences: []string{piRuntime, listedService}},
}

func serviceSecret(name string) string { return "test-secret-for-" + name + "-long-enough-to-pass" }

func (h *harness) serviceToken(name string) string {
	h.t.Helper()
	status, body := h.do("POST", "/v1/token", "", map[string]string{
		"grant_type": "client_credentials", "client_id": name, "client_secret": serviceSecret(name),
	})
	h.wantStatus(status, body, http.StatusOK)
	return body["access_token"].(string)
}

func (h *harness) exchange(name, grantID string) (int, map[string]any) {
	h.t.Helper()
	return h.do("POST", "/v1/token", "", map[string]string{
		"grant_type": "agent_grant", "client_id": name, "client_secret": serviceSecret(name), "grant_id": grantID,
	})
}

func (h *harness) mint(name, grantID string) string {
	h.t.Helper()
	status, body := h.exchange(name, grantID)
	h.wantStatus(status, body, http.StatusOK)
	return body["access_token"].(string)
}

func (h *harness) wantStopped(name, grantID string) {
	h.t.Helper()
	status, body := h.exchange(name, grantID)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		h.t.Fatalf("exchange still answers: %d %v", status, body)
	}
}

// grant creates a grant through the API and returns its ID.
func (h *harness) grant(name, subject string, actions, audiences []string) string {
	h.t.Helper()
	status, body := h.createGrant(name, map[string]any{"subject_token": subject, "actions": actions, "audiences": audiences})
	h.wantStatus(status, body, http.StatusCreated)
	return body["id"].(string)
}

func (h *harness) createGrant(name string, req map[string]any) (int, map[string]any) {
	h.t.Helper()
	return h.do("POST", "/v1/grants", h.serviceToken(name), req)
}

func unverifiedClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(data, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// admitted is one user in a room, with the grant their call produced.
func (h *harness) admitted(tenant string) (userID, userToken, grantID string) {
	h.t.Helper()
	h.tenant(tenant)
	userID = h.user("ada", map[string]string{tenant: directory.RoleMember})
	userToken = h.login("ada", "")
	status, body := h.do("POST", "/v1/rooms/admission", userToken, map[string]string{"room": "r"})
	h.wantStatus(status, body, http.StatusOK)
	claims := unverifiedClaims(h.t, body["room_token"].(string))
	attributes, _ := claims["attributes"].(map[string]any)
	grantID, _ = attributes[agents.GrantAttribute].(string)
	if !strings.HasPrefix(grantID, "grt_") {
		h.t.Fatalf("room token has no grant attribute: %v", claims)
	}
	if video := claims["video"].(map[string]any); video["canUpdateOwnMetadata"] != nil {
		h.t.Fatalf("a client must not be able to rewrite its attributes: %v", video)
	}
	return userID, userToken, grantID
}

func TestAdmissionGrantExchangesForDelegatedToken(t *testing.T) {
	h := newHarness(t, true)
	userID, _, grantID := h.admitted("ten_acme")

	status, body := h.exchange(voiceRuntime, grantID)
	h.wantStatus(status, body, http.StatusOK)
	if body["user_id"] != userID || body["tenant_id"] != "ten_acme" {
		t.Errorf("exchange names the wrong user: %v", body)
	}
	claims := unverifiedClaims(t, body["access_token"].(string))
	if claims["sub"] != userID || claims["tid"] != "ten_acme" || claims["grant"] != grantID || claims["scope"] != "agent:use" {
		t.Errorf("wrong claims: %v", claims)
	}
	if act := claims["act"].(map[string]any); act["sub"] != agents.ServiceID(voiceRuntime) {
		t.Errorf("wrong actor: %v", act)
	}
	if aud := claims["aud"].([]any); !slices.Equal(aud, []any{piRuntime}) {
		t.Errorf("audience must be the grant's services and never t10: %v", aud)
	}
	if claims["sid"] != nil {
		t.Errorf("a delegated token is not a session: %v", claims)
	}
	life := time.Duration(claims["exp"].(float64)-claims["iat"].(float64)) * time.Second
	if life > agents.DelegatedTokenTTL {
		t.Errorf("token lives %s", life)
	}
	if h.auditCount("grant.create", "success") != 1 {
		t.Error("creating a grant wrote no audit row")
	}
}

func TestDelegatedTokenStopsAtGrantExpiry(t *testing.T) {
	h := newHarness(t, true)
	_, _, grantID := h.admitted("ten_acme")
	if _, err := h.pool.Exec(context.Background(),
		"UPDATE auth.agent_grants SET expires_at = now() + interval '1 minute' WHERE id = $1", grantID); err != nil {
		t.Fatal(err)
	}
	claims := unverifiedClaims(t, h.mint(voiceRuntime, grantID))
	if left := time.Until(time.Unix(int64(claims["exp"].(float64)), 0)); left > time.Minute {
		t.Errorf("token outlives its grant by %s", left-time.Minute)
	}
}

func TestOnlyTheRuntimeOrAListedServiceCanExchange(t *testing.T) {
	h := newHarness(t, true)
	_, _, grantID := h.admitted("ten_acme")

	status, body := h.do("POST", "/v1/token", "", map[string]string{
		"grant_type": "agent_grant", "client_id": voiceRuntime, "client_secret": "wrong", "grant_id": grantID,
	})
	h.wantStatus(status, body, http.StatusUnauthorized)
	status, body = h.do("POST", "/v1/token", "", map[string]string{
		"grant_type": "agent_grant", "client_id": voiceRuntime, "grant_id": grantID,
	})
	h.wantStatus(status, body, http.StatusUnauthorized)

	h.wantStopped(otherService, grantID)
	if h.auditCount("grant.exchange", "denied") != 1 {
		t.Error("the refusal wrote no audit row")
	}
	// agent-pi is listed on the voice grant, so it can renew.
	status, body = h.exchange(piRuntime, grantID)
	h.wantStatus(status, body, http.StatusOK)
	h.wantStopped(voiceRuntime, "grt_unknown")
}

func TestTokensStayOnTheirSideOfTheBoundary(t *testing.T) {
	h := newHarness(t, true)
	_, userToken, grantID := h.admitted("ten_acme")
	service := h.serviceToken(voiceRuntime)
	delegated := h.mint(voiceRuntime, grantID)

	if claims := unverifiedClaims(t, service); claims["tid"] != nil || claims["scope"] != nil || claims["sid"] != nil {
		t.Errorf("a service token must carry no tenant, scope or session: %v", claims)
	}
	for name, token := range map[string]string{"service": service, "delegated": delegated} {
		status, body := h.do("GET", "/v1/me", token, nil)
		if status != http.StatusUnauthorized {
			t.Errorf("%s token reached a user route: %d %v", name, status, body)
		}
		status, _ = h.do("POST", "/v1/rooms/admission", token, map[string]string{"room": "r"})
		if status != http.StatusUnauthorized {
			t.Errorf("%s token reached admission: %d", name, status)
		}
	}
	for name, token := range map[string]string{"user": userToken, "delegated": delegated, "none": ""} {
		status, _ := h.do("GET", "/v1/grants/"+grantID+"/chain", token, nil)
		if status != http.StatusUnauthorized {
			t.Errorf("%s token reached a service route: %d", name, status)
		}
	}
}

func TestDisabledServiceStopsAtOnce(t *testing.T) {
	h := newHarness(t, true)
	_, _, grantID := h.admitted("ten_acme")
	service := h.serviceToken(voiceRuntime)
	child := h.grant(piRuntime, h.mint(piRuntime, grantID), []string{"agent:use"}, []string{piRuntime})
	if err := h.id.SetServiceStatus(context.Background(), "test", voiceRuntime, identity.ServiceDisabled); err != nil {
		t.Fatal(err)
	}
	status, body := h.do("GET", "/v1/grants/"+grantID+"/chain", service, nil)
	h.wantStatus(status, body, http.StatusUnauthorized)
	status, body = h.exchange(voiceRuntime, grantID)
	h.wantStatus(status, body, http.StatusUnauthorized)
	// A chain is only as good as the runtimes along it.
	h.wantStopped(piRuntime, child)
}

func TestSecretRotationKeepsBothValidUntilFinished(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	login := func(secret string) int {
		status, _ := h.do("POST", "/v1/token", "", map[string]string{
			"grant_type": "client_credentials", "client_id": piRuntime, "client_secret": secret,
		})
		return status
	}
	next, err := h.id.RotateServiceSecret(ctx, "test", piRuntime)
	if err != nil {
		t.Fatal(err)
	}
	if login(serviceSecret(piRuntime)) != http.StatusOK || login(next) != http.StatusOK {
		t.Fatal("both secrets must work during a rotation")
	}
	if err := h.id.FinishServiceRotation(ctx, "test", piRuntime); err != nil {
		t.Fatal(err)
	}
	if login(serviceSecret(piRuntime)) != http.StatusUnauthorized || login(next) != http.StatusOK {
		t.Fatal("only the new secret may work afterwards")
	}
	if err := h.id.FinishServiceRotation(ctx, "test", piRuntime); err == nil {
		t.Fatal("finishing with nothing to finish must not wipe the secret")
	}
}

func TestShortServiceSecretIsRefused(t *testing.T) {
	h := newHarness(t, true)
	if _, err := h.id.AddServiceAccount(context.Background(), "test", "short", "too-short"); err == nil {
		t.Fatal("accepted a short secret")
	}
	if _, err := h.id.AddServiceAccount(context.Background(), "test", "t10", ""); err == nil {
		t.Fatal("a service named t10 would receive every user token")
	}
}

func TestRootGrantStaysInsideTheRuntimeList(t *testing.T) {
	h := newHarness(t, true)
	userID, userToken, _ := h.admitted("ten_acme")

	id := h.grant(piRuntime, userToken, []string{"crm:read"}, []string{listedService})
	claims := unverifiedClaims(t, h.mint(piRuntime, id))
	if claims["sub"] != userID || claims["scope"] != "crm:read" {
		t.Errorf("wrong claims: %v", claims)
	}

	for name, req := range map[string]map[string]any{
		"unlisted action":   {"actions": []string{"crm:delete"}, "audiences": []string{piRuntime}},
		"unlisted audience": {"actions": []string{"crm:read"}, "audiences": []string{"deals"}},
		"t10 audience":      {"actions": []string{"crm:read"}, "audiences": []string{"t10"}},
		"wildcard":          {"actions": []string{"*"}, "audiences": []string{piRuntime}},
		"no actions":        {"actions": []string{}, "audiences": []string{piRuntime}},
		"no audiences":      {"actions": []string{"crm:read"}, "audiences": []string{}},
		"bad constraints":   {"actions": []string{"crm:read"}, "audiences": []string{piRuntime}, "constraints": []int{1}},
		"null constraints":  {"actions": []string{"crm:read"}, "audiences": []string{piRuntime}, "constraints": "x"},
	} {
		req["subject_token"] = userToken
		if status, body := h.createGrant(piRuntime, req); status != http.StatusBadRequest {
			t.Errorf("%s: %d %v", name, status, body)
		}
	}

	// A listed service that is not a runtime can't start anything.
	status, body := h.createGrant(listedService, map[string]any{
		"subject_token": userToken, "actions": []string{"crm:read"}, "audiences": []string{listedService},
	})
	h.wantStatus(status, body, http.StatusBadRequest)
}

func TestRootGrantNeedsAUserToken(t *testing.T) {
	h := newHarness(t, true)
	_, _, _ = h.admitted("ten_acme")
	for name, subject := range map[string]string{"service": h.serviceToken(piRuntime), "garbage": "x.y.z", "empty": ""} {
		status, body := h.createGrant(piRuntime, map[string]any{
			"subject_token": subject, "actions": []string{"crm:read"}, "audiences": []string{piRuntime},
		})
		if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Errorf("%s: %d %v", name, status, body)
		}
	}
}

func TestTheUserAndTenantComeFromTheToken(t *testing.T) {
	h := newHarness(t, true)
	userID, userToken, _ := h.admitted("ten_acme")
	h.tenant("ten_other")
	status, body := h.createGrant(piRuntime, map[string]any{
		"subject_token": userToken, "actions": []string{"crm:read"}, "audiences": []string{piRuntime},
		"user_id": "usr_victim", "tenant_id": "ten_other",
	})
	h.wantStatus(status, body, http.StatusCreated)
	if body["user_id"] != userID || body["tenant_id"] != "ten_acme" {
		t.Errorf("body chose the grant's owner: %v", body)
	}
}

func TestChildCanOnlyNarrow(t *testing.T) {
	h := newHarness(t, true)
	_, userToken, _ := h.admitted("ten_acme")
	root := h.grant(piRuntime, userToken, []string{"agent:use", "crm:read"}, []string{piRuntime, listedService})
	token := h.mint(piRuntime, root)

	narrowed := h.grant(piRuntime, token, []string{"crm:read"}, []string{listedService})
	childToken := h.mint(piRuntime, narrowed)
	claims := unverifiedClaims(t, childToken)
	if claims["scope"] != "crm:read" || !slices.Equal(claims["aud"].([]any), []any{listedService}) {
		t.Errorf("wrong child claims: %v", claims)
	}

	// Both are on the runtime's list, so only the parent can refuse them.
	status, body := h.createGrant(piRuntime, map[string]any{
		"subject_token": childToken, "actions": []string{"agent:use"}, "audiences": []string{listedService},
	})
	h.wantStatus(status, body, http.StatusBadRequest)
	status, body = h.createGrant(piRuntime, map[string]any{
		"subject_token": childToken, "actions": []string{"crm:read"}, "audiences": []string{piRuntime},
	})
	h.wantStatus(status, body, http.StatusBadRequest)
}

func TestChildCannotOutliveItsParent(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	_, userToken, _ := h.admitted("ten_acme")
	root := h.grant(piRuntime, userToken, []string{"crm:read"}, []string{piRuntime})
	if _, err := h.pool.Exec(ctx, "UPDATE auth.agent_grants SET expires_at = now() + interval '1 hour' WHERE id = $1", root); err != nil {
		t.Fatal(err)
	}
	status, body := h.createGrant(piRuntime, map[string]any{
		"subject_token": h.mint(piRuntime, root), "actions": []string{"crm:read"}, "audiences": []string{piRuntime},
		"ttl_seconds": 80000,
	})
	h.wantStatus(status, body, http.StatusCreated)
	expires, err := time.Parse(time.RFC3339, body["expires_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(expires) > time.Hour {
		t.Errorf("child expires in %s, after its parent", time.Until(expires))
	}
}

func TestGrantLifetimeIsCapped(t *testing.T) {
	h := newHarness(t, true)
	_, userToken, _ := h.admitted("ten_acme")
	status, body := h.createGrant(piRuntime, map[string]any{
		"subject_token": userToken, "actions": []string{"crm:read"}, "audiences": []string{piRuntime}, "ttl_seconds": 10 * 86400,
	})
	h.wantStatus(status, body, http.StatusCreated)
	expires, err := time.Parse(time.RFC3339, body["expires_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(expires) > agents.MaxGrantLife {
		t.Errorf("grant lasts %s", time.Until(expires))
	}
}

func TestChainDepthIsCapped(t *testing.T) {
	h := newHarness(t, true)
	_, userToken, _ := h.admitted("ten_acme")
	id := h.grant(piRuntime, userToken, []string{"crm:read"}, []string{piRuntime})
	for depth := 2; depth <= agents.MaxGrantDepth; depth++ {
		id = h.grant(piRuntime, h.mint(piRuntime, id), []string{"crm:read"}, []string{piRuntime})
	}
	status, body := h.createGrant(piRuntime, map[string]any{
		"subject_token": h.mint(piRuntime, id), "actions": []string{"crm:read"}, "audiences": []string{piRuntime},
	})
	h.wantStatus(status, body, http.StatusBadRequest)
}

func TestChainEndpointReturnsEveryConstraintRootFirst(t *testing.T) {
	h := newHarness(t, true)
	_, userToken, _ := h.admitted("ten_acme")
	status, body := h.createGrant(piRuntime, map[string]any{
		"subject_token": userToken, "actions": []string{"crm:read"}, "audiences": []string{piRuntime, listedService},
		"constraints": map[string]any{"region": "north"},
	})
	h.wantStatus(status, body, http.StatusCreated)
	root := body["id"].(string)
	status, body = h.createGrant(piRuntime, map[string]any{
		"subject_token": h.mint(piRuntime, root), "actions": []string{"crm:read"}, "audiences": []string{listedService},
		"constraints": map[string]any{"deal": "d1"},
	})
	h.wantStatus(status, body, http.StatusCreated)
	child := body["id"].(string)

	status, body = h.do("GET", "/v1/grants/"+child+"/chain", h.serviceToken(listedService), nil)
	h.wantStatus(status, body, http.StatusOK)
	chain := body["chain"].([]any)
	if len(chain) != 2 {
		t.Fatalf("chain: %v", chain)
	}
	first, second := chain[0].(map[string]any), chain[1].(map[string]any)
	if first["id"] != root || second["id"] != child {
		t.Errorf("order: %v", chain)
	}
	if first["constraints"].(map[string]any)["region"] != "north" || second["constraints"].(map[string]any)["deal"] != "d1" {
		t.Errorf("constraints lost: %v", chain)
	}

	status, body = h.do("GET", "/v1/grants/"+child+"/chain", h.serviceToken(otherService), nil)
	h.wantStatus(status, body, http.StatusBadRequest)
}

func TestRevokingAGrantStopsItsDescendants(t *testing.T) {
	h := newHarness(t, true)
	_, userToken, _ := h.admitted("ten_acme")
	root := h.grant(piRuntime, userToken, []string{"crm:read"}, []string{piRuntime})
	child := h.grant(piRuntime, h.mint(piRuntime, root), []string{"crm:read"}, []string{piRuntime})
	grandchild := h.grant(piRuntime, h.mint(piRuntime, child), []string{"crm:read"}, []string{piRuntime})

	status, body := h.do("POST", "/v1/grants/"+root+"/revoke", h.serviceToken(otherService), nil)
	h.wantStatus(status, body, http.StatusBadRequest)
	h.mint(piRuntime, grandchild)

	status, _ = h.do("POST", "/v1/grants/"+root+"/revoke", h.serviceToken(piRuntime), nil)
	if status != http.StatusNoContent {
		t.Fatalf("revoke: %d", status)
	}
	h.wantStopped(piRuntime, root)
	h.wantStopped(piRuntime, grandchild)
	status, body = h.do("GET", "/v1/grants/"+grandchild+"/chain", h.serviceToken(piRuntime), nil)
	h.wantStatus(status, body, http.StatusBadRequest)
	if h.auditCount("grant.revoke", "success") != 1 {
		t.Error("revoking wrote no audit row")
	}
}

func TestChildOfARevokedParentIsRefused(t *testing.T) {
	h := newHarness(t, true)
	_, userToken, _ := h.admitted("ten_acme")
	root := h.grant(piRuntime, userToken, []string{"crm:read"}, []string{piRuntime})
	token := h.mint(piRuntime, root)
	h.do("POST", "/v1/grants/"+root+"/revoke", h.serviceToken(piRuntime), nil)
	status, body := h.createGrant(piRuntime, map[string]any{
		"subject_token": token, "actions": []string{"crm:read"}, "audiences": []string{piRuntime},
	})
	h.wantStatus(status, body, http.StatusBadRequest)
}

func TestAccountEventsStopGrants(t *testing.T) {
	ctx := context.Background()
	inactive, active := directory.MemberInactive, directory.MemberActive

	t.Run("sign out everywhere", func(t *testing.T) {
		h := newHarness(t, true)
		userID, _, grantID := h.admitted("ten_acme")
		if err := h.id.SignOutEverywhere(ctx, userID); err != nil {
			t.Fatal(err)
		}
		h.wantStopped(voiceRuntime, grantID)
	})

	t.Run("password reset", func(t *testing.T) {
		h := newHarness(t, true)
		userID, _, grantID := h.admitted("ten_acme")
		token, err := h.id.IssueReset(ctx, "user:admin", "platform", userID)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.id.ResetPassword(ctx, token, "a-brand-new-password-1"); err != nil {
			t.Fatal(err)
		}
		h.wantStopped(voiceRuntime, grantID)
	})

	t.Run("membership stays stopped when restored", func(t *testing.T) {
		h := newHarness(t, true)
		userID, _, grantID := h.admitted("ten_acme")
		if _, err := h.dir.UpdateMember(ctx, "test", "ten_acme", userID, directory.MemberUpdate{Status: &inactive}); err != nil {
			t.Fatal(err)
		}
		h.wantStopped(voiceRuntime, grantID)
		if _, err := h.dir.UpdateMember(ctx, "test", "ten_acme", userID, directory.MemberUpdate{Status: &active}); err != nil {
			t.Fatal(err)
		}
		h.wantStopped(voiceRuntime, grantID)
	})

	t.Run("another tenant is left alone", func(t *testing.T) {
		h := newHarness(t, true)
		h.tenant("ten_acme")
		h.tenant("ten_other")
		userID := h.user("ada", map[string]string{"ten_acme": directory.RoleMember, "ten_other": directory.RoleMember})
		acme, other := h.login("ada", "ten_acme"), h.login("ada", "ten_other")
		kept := h.grant(piRuntime, acme, []string{"crm:read"}, []string{piRuntime})
		stopped := h.grant(piRuntime, other, []string{"crm:read"}, []string{piRuntime})
		if _, err := h.dir.UpdateMember(ctx, "test", "ten_other", userID, directory.MemberUpdate{Status: &inactive}); err != nil {
			t.Fatal(err)
		}
		h.wantStopped(piRuntime, stopped)
		h.mint(piRuntime, kept)
	})

	t.Run("user suspended", func(t *testing.T) {
		h := newHarness(t, true)
		userID, _, grantID := h.admitted("ten_acme")
		if _, err := h.pool.Exec(ctx, "UPDATE auth.users SET status = 'suspended' WHERE id = $1", userID); err != nil {
			t.Fatal(err)
		}
		h.wantStopped(voiceRuntime, grantID)
	})

	t.Run("tenant suspended, and back", func(t *testing.T) {
		h := newHarness(t, true)
		_, _, grantID := h.admitted("ten_acme")
		if err := h.dir.SetTenantStatus(ctx, "test", "ten_acme", directory.TenantSuspended); err != nil {
			t.Fatal(err)
		}
		h.wantStopped(voiceRuntime, grantID)
		if err := h.dir.SetTenantStatus(ctx, "test", "ten_acme", directory.TenantActive); err != nil {
			t.Fatal(err)
		}
		h.mint(voiceRuntime, grantID)
	})

	t.Run("one device signing out leaves a call running", func(t *testing.T) {
		h := newHarness(t, true)
		_, userToken, grantID := h.admitted("ten_acme")
		status, _ := h.do("POST", "/v1/logout", userToken, nil)
		if status >= 300 {
			t.Fatalf("logout: %d", status)
		}
		h.mint(voiceRuntime, grantID)
	})
}

func TestExtend(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true)
	_, userToken, _ := h.admitted("ten_acme")
	h.user("eve", map[string]string{"ten_acme": directory.RoleMember})
	root := h.grant(piRuntime, userToken, []string{"crm:read"}, []string{piRuntime})
	service := h.serviceToken(piRuntime)
	extend := func(id, subject string) (int, map[string]any) {
		return h.do("POST", "/v1/grants/"+id+"/extend", service, map[string]string{"subject_token": subject})
	}
	setExpiry := func(sql string) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, "UPDATE auth.agent_grants SET "+sql+" WHERE id = $1", root); err != nil {
			t.Fatal(err)
		}
	}

	status, body := extend(root, h.login("eve", ""))
	h.wantStatus(status, body, http.StatusBadRequest)
	status, body = extend(root, h.mint(piRuntime, root))
	h.wantStatus(status, body, http.StatusBadRequest)

	// An expired grant pauses a run, and a live user renews it.
	setExpiry("expires_at = now() - interval '1 minute'")
	status, body = h.exchange(piRuntime, root)
	if status != http.StatusBadRequest || body["error"] != "grant_expired" {
		t.Fatalf("expired grant: %d %v", status, body)
	}
	status, body = extend(root, userToken)
	h.wantStatus(status, body, http.StatusOK)
	h.mint(piRuntime, root)

	// Created 23 hours ago, so one hour is all that's left.
	setExpiry("created_at = now() - interval '23 hours', expires_at = now() + interval '10 minutes'")
	status, body = extend(root, userToken)
	h.wantStatus(status, body, http.StatusOK)
	var left time.Duration
	if err := h.pool.QueryRow(ctx, "SELECT expires_at - now() FROM auth.agent_grants WHERE id = $1", root).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left < 50*time.Minute || left > time.Hour {
		t.Errorf("24-hour cap: grant runs %s more", left)
	}
	// Extending never shortens.
	setExpiry("created_at = now() - interval '1 hour', expires_at = now() + interval '20 hours'")
	status, body = extend(root, userToken)
	h.wantStatus(status, body, http.StatusOK)
	if err := h.pool.QueryRow(ctx, "SELECT expires_at - now() FROM auth.agent_grants WHERE id = $1", root).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left < 19*time.Hour {
		t.Errorf("extending shortened the grant to %s", left)
	}
	setExpiry("expires_at = now() - interval '1 minute', created_at = now() - interval '25 hours'")
	status, body = extend(root, userToken)
	if status != http.StatusBadRequest || body["error"] != "grant_expired" {
		t.Fatalf("past the cap: %d %v", status, body)
	}

	h.do("POST", "/v1/grants/"+root+"/revoke", service, nil)
	setExpiry("created_at = now(), expires_at = now() + interval '1 hour'")
	status, body = extend(root, userToken)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("revoked grant was extended: %d %v", status, body)
	}
}

func TestDatabaseRefusesAChainAcrossUsersOrTenants(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	h.tenant("ten_acme")
	h.tenant("ten_other")
	ada := h.user("ada", map[string]string{"ten_acme": directory.RoleMember, "ten_other": directory.RoleMember})
	eve := h.user("eve", map[string]string{"ten_acme": directory.RoleMember})
	root := h.grant(piRuntime, h.login("ada", "ten_acme"), []string{"crm:read"}, []string{piRuntime})
	insert := func(user, tenant string, depth int) error {
		_, err := h.pool.Exec(ctx,
			`INSERT INTO auth.agent_grants (id, parent_id, runtime_id, user_id, tenant_id, actions, audiences, depth, expires_at)
			 VALUES ($1, $2, $3, $4, $5, '{crm:read}', '{agent-pi}', $6, now() + interval '1 hour')`,
			fmt.Sprintf("grt_test%d", depth), root, agents.ServiceID(piRuntime), user, tenant, depth)
		return err
	}
	if insert(eve, "ten_acme", 2) == nil {
		t.Error("a child moved to another user")
	}
	if insert(ada, "ten_other", 2) == nil {
		t.Error("a child moved to another tenant")
	}
	if insert(ada, "ten_acme", 5) == nil {
		t.Error("a chain passed the depth limit")
	}
}

func TestRuntimeListRefusesWideEntries(t *testing.T) {
	path := t.TempDir() + "/clients.yaml"
	write := func(body string) error {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := agents.LoadRuntimes(path)
		return err
	}
	if err := write("runtimes:\n  - {name: pi, actions: [crm:read], audiences: [crm]}\n"); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"wildcard":   "runtimes:\n  - {name: pi, actions: ['crm:*'], audiences: [crm]}\n",
		"star":       "runtimes:\n  - {name: pi, actions: ['*'], audiences: [crm]}\n",
		"t10":        "runtimes:\n  - {name: pi, actions: [crm:read], audiences: [t10]}\n",
		"empty":      "runtimes:\n  - {name: pi, actions: [], audiences: [crm]}\n",
		"repeated":   "runtimes:\n  - {name: pi, actions: [a:b], audiences: [crm]}\n  - {name: pi, actions: [a:b], audiences: [crm]}\n",
		"two voices": "runtimes:\n  - {name: pa, voice: true, actions: [a:b], audiences: [crm]}\n  - {name: pi, voice: true, actions: [a:b], audiences: [crm]}\n",
		"bad name":   "runtimes:\n  - {name: 'Pi X', actions: [a:b], audiences: [crm]}\n",
	} {
		if write(body) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestAgentGrantTokenRequestAcceptsAForm(t *testing.T) {
	h := newHarness(t, true)
	_, _, grantID := h.admitted("ten_acme")
	status, body := h.token(url.Values{
		"grant_type": {"agent_grant"}, "client_id": {voiceRuntime}, "client_secret": {serviceSecret(voiceRuntime)}, "grant_id": {grantID},
	})
	h.wantStatus(status, body, http.StatusOK)
}
