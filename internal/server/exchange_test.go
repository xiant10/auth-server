package server

import (
	"net/http"
	"slices"
	"testing"

	"t10-auth-server/internal/directory"
)

func (h *harness) tokenExchange(caller, subject, audience string) (int, map[string]any) {
	h.t.Helper()
	return h.do("POST", "/v1/token", "", map[string]string{
		"grant_type": grantTypeTokenExchange, "client_id": caller, "client_secret": serviceSecret(caller),
		"subject_token": subject, "audience": audience,
	})
}

func audiences(t *testing.T, token string) []string {
	t.Helper()
	var out []string
	for _, a := range unverifiedClaims(t, token)["aud"].([]any) {
		out = append(out, a.(string))
	}
	return out
}

// A gated runtime's tokens are good only at the tool gateway, which trades one
// for a token the module accepts, saying the same thing about who and why.
func TestToolGatewayTokensAndExchange(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	userID := h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	user := h.login("ada", "ten_acme")
	grant := h.grant(gatedRuntime, user, []string{"crm:read"}, []string{listedService, toolGateway})
	run := h.mint(gatedRuntime, grant)
	if got := audiences(t, run); !slices.Equal(got, []string{toolGateway}) {
		t.Fatalf("a gated run's token is for %v", got)
	}
	// A grant that lists the model gateway keeps it beside the tool gateway,
	// because model calls don't go through the tool gateway.
	modelled := h.mint(gatedRuntime, h.grant(gatedRuntime, user, []string{"crm:read"}, []string{listedService, toolGateway, modelGateway}))
	if got := audiences(t, modelled); !slices.Equal(got, []string{toolGateway, modelGateway}) {
		t.Fatalf("a gated run's token with the model gateway is for %v", got)
	}
	// A runtime without a tool audience mints as before.
	plain := h.mint(piRuntime, h.grant(piRuntime, user, []string{"crm:read"}, []string{listedService}))
	if got := audiences(t, plain); !slices.Contains(got, listedService) {
		t.Fatalf("an ungated token is for %v", got)
	}

	status, body := h.tokenExchange(toolGateway, run, listedService)
	h.wantStatus(status, body, http.StatusOK)
	module := body["access_token"].(string)
	claims, original := unverifiedClaims(t, module), unverifiedClaims(t, run)
	if got := audiences(t, module); !slices.Equal(got, []string{listedService}) {
		t.Fatalf("exchanged token is for %v", got)
	}
	for _, claim := range []string{"sub", "tid", "grant", "trg", "scope"} {
		if claims[claim] != original[claim] {
			t.Errorf("%s changed: %v to %v", claim, original[claim], claims[claim])
		}
	}
	if claims["sub"] != userID || claims["act"].(map[string]any)["sub"] != "svc_"+gatedRuntime || claims["exp"].(float64) > original["exp"].(float64) {
		t.Errorf("exchanged claims: %v", claims)
	}

	for name, tc := range map[string]struct{ caller, subject, audience string }{
		"a service that may not exchange": {listedService, run, otherService},
		"an audience off the grant":       {toolGateway, run, otherService},
		"the platform audience":           {toolGateway, run, "t10"},
		"a token not presented to it":     {toolGateway, plain, listedService},
		"a person's own token":            {toolGateway, user, listedService},
	} {
		if status, body := h.tokenExchange(tc.caller, tc.subject, tc.audience); status != http.StatusBadRequest {
			t.Errorf("%s: %d %v", name, status, body)
		}
	}

	// Revoking the grant stops the exchange, as it stops every mint.
	if status, body := h.do("POST", "/v1/grants/"+grant+"/revoke", h.serviceToken(gatedRuntime), nil); status != http.StatusNoContent {
		t.Fatalf("revoke: %d %v", status, body)
	}
	if status, _ := h.tokenExchange(toolGateway, run, listedService); status != http.StatusBadRequest {
		t.Errorf("exchanged for a revoked grant: %d", status)
	}
}
