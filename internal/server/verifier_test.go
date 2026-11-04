package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"t10-auth-server/internal/identity"
	"t10-auth-server/verifier"
)

func (h *harness) verifier(name string) *verifier.Verifier {
	h.t.Helper()
	v, err := verifier.New(verifier.Config{
		Issuer: "http://localhost:8081", URL: h.url, Service: name, ClientSecret: serviceSecret(name),
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return v
}

func TestVerifierSeparatesPeopleAgentsAndServices(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	userID, userToken, grantID := h.admitted("ten_acme")
	v := h.verifier(piRuntime)

	person, err := v.Verify(ctx, userToken)
	if err != nil {
		t.Fatal(err)
	}
	if person.UserID != userID || person.TenantID != "ten_acme" || person.Agent != nil || !person.Allows("anything:at-all") {
		t.Errorf("person: %+v", person)
	}

	agent, err := v.Verify(ctx, h.mint(voiceRuntime, grantID))
	if err != nil {
		t.Fatal(err)
	}
	if agent.UserID != userID || agent.Agent == nil || agent.Agent.GrantID != grantID || agent.Agent.Runtime != "svc_"+voiceRuntime || agent.Agent.Trigger != "voice" {
		t.Fatalf("agent: %+v", agent)
	}
	if !agent.Allows("agent:use") || agent.Allows("crm:read") {
		t.Errorf("an agent has only its grant's actions: %+v", agent.Scopes)
	}

	service, err := v.Verify(ctx, h.serviceToken(voiceRuntime))
	if err != nil {
		t.Fatal(err)
	}
	if service.UserID != "" || service.ServiceID != "svc_"+voiceRuntime || service.Allows("agent:use") {
		t.Errorf("a service is not a person: %+v", service)
	}
}

func TestVerifierReturnsTheWholeChain(t *testing.T) {
	h := newHarness(t, true)
	_, userToken, _ := h.admitted("ten_acme")
	status, body := h.createGrant(piRuntime, map[string]any{
		"subject_token": userToken, "actions": []string{"agent:use", "crm:read"}, "audiences": []string{piRuntime, listedService},
		"constraints": map[string]any{"region": "north"},
	})
	h.wantStatus(status, body, http.StatusCreated)
	root := body["id"].(string)
	child := h.grant(piRuntime, h.mint(piRuntime, root), []string{"crm:read"}, []string{listedService})

	got, err := h.verifier(listedService).Verify(context.Background(), h.mint(piRuntime, child))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Agent.Chain) != 2 || got.Agent.Chain[0].ID != root || !got.Allows("crm:read") || got.Allows("agent:use") {
		t.Fatalf("chain: %+v", got.Agent)
	}
	if c := got.Constraints(); len(c) != 2 || !strings.Contains(string(c[0]), "north") {
		t.Errorf("constraints: %s", c)
	}
}

func TestVerifierRefuses(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	_, _, grantID := h.admitted("ten_acme")
	delegated := h.mint(voiceRuntime, grantID)
	status, body := h.do("POST", "/v1/rooms/admission", h.login("ada", ""), map[string]string{"room": "r"})
	h.wantStatus(status, body, http.StatusOK)

	if _, err := h.verifier(listedService).Verify(ctx, delegated); !errors.Is(err, verifier.ErrInvalidToken) {
		t.Errorf("a token for another service: %v", err)
	}
	if _, err := h.verifier(piRuntime).Verify(ctx, body["assertion"].(string)); !errors.Is(err, verifier.ErrInvalidToken) {
		t.Errorf("a room assertion: %v", err)
	}

	other, err := identity.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	forged, _, err := identity.NewIssuer("http://localhost:8081", identity.NewKeySet(other, nil)).MintAccess("usr_x", "ten_acme", "ses_x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.verifier(piRuntime).Verify(ctx, forged); !errors.Is(err, verifier.ErrInvalidToken) {
		t.Errorf("a forged token: %v", err)
	}
	const noneToken = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c3JfeCIsImF1ZCI6InQxMCIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MSJ9."
	if _, err := h.verifier(piRuntime).Verify(ctx, noneToken); !errors.Is(err, verifier.ErrInvalidToken) {
		t.Errorf("alg none: %v", err)
	}
	wrongIssuer, err := verifier.New(verifier.Config{Issuer: "https://elsewhere.example", URL: h.url, Service: piRuntime})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongIssuer.Verify(ctx, delegated); !errors.Is(err, verifier.ErrInvalidToken) {
		t.Errorf("wrong issuer: %v", err)
	}
}

func TestVerifierFailsClosedWithoutAChain(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	_, _, grantID := h.admitted("ten_acme")
	delegated := h.mint(voiceRuntime, grantID)

	noSecret, err := verifier.New(verifier.Config{Issuer: "http://localhost:8081", URL: h.url, Service: piRuntime, ClientSecret: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noSecret.Verify(ctx, delegated); !errors.Is(err, verifier.ErrGrantUnavailable) {
		t.Errorf("no service credentials: %v", err)
	}

	v := h.verifier(piRuntime)
	if _, err := v.Verify(ctx, delegated); err != nil {
		t.Fatal(err)
	}
	h.do("POST", "/v1/grants/"+grantID+"/revoke", h.serviceToken(voiceRuntime), nil)
	if _, err := h.verifier(piRuntime).Verify(ctx, delegated); !errors.Is(err, verifier.ErrGrantUnavailable) {
		t.Errorf("a revoked grant on a live token: %v", err)
	}
	if _, err := v.Verify(ctx, delegated); err != nil {
		t.Errorf("the cached chain should last its minute: %v", err)
	}
}

func TestVerifierChainCacheExpires(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	_, _, grantID := h.admitted("ten_acme")
	delegated := h.mint(voiceRuntime, grantID)
	now := time.Now()
	v, err := verifier.New(verifier.Config{
		Issuer: "http://localhost:8081", URL: h.url, Service: piRuntime, ClientSecret: serviceSecret(piRuntime),
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(ctx, delegated); err != nil {
		t.Fatal(err)
	}
	h.do("POST", "/v1/grants/"+grantID+"/revoke", h.serviceToken(voiceRuntime), nil)
	now = now.Add(61 * time.Second)
	if _, err := v.Verify(ctx, delegated); !errors.Is(err, verifier.ErrGrantUnavailable) {
		t.Errorf("a revoked chain outlived its cache: %v", err)
	}
}
