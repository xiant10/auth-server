package identity

import (
	"testing"
	"time"
)

func TestBrowserLogoutTokenIsScopedAndExpires(t *testing.T) {
	issuer := testIssuer(t)
	token, err := issuer.MintBrowserLogout("user", "ses", "https://work.example/signed-out")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := issuer.VerifyBrowserLogout(token)
	if err != nil || claims.Subject != "user" || claims.LogoutRedirect != "https://work.example/signed-out" {
		t.Fatalf("claims: %v %v", claims, err)
	}
	if _, err := issuer.Verify(token); err == nil {
		t.Fatal("logout ticket accepted as access token")
	}
	access, _, _ := issuer.MintAccess("user", "tenant", "session")
	if _, err := issuer.VerifyBrowserLogout(access); err == nil {
		t.Fatal("access token accepted as logout ticket")
	}
	if _, err := issuer.VerifyBrowserLogout(token + "tampered"); err == nil {
		t.Fatal("tampered ticket accepted")
	}
	issuer.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, err := issuer.VerifyBrowserLogout(token); err == nil {
		t.Fatal("expired ticket accepted")
	}
}
