package identity

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testIssuer(t *testing.T) *Issuer {
	t.Helper()
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return NewIssuer("http://localhost:8081", NewKeySet(key, nil))
}

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		input, kind, value string
		wantErr            bool
	}{
		{input: "Ada", kind: KindUsername, value: "ada"},
		{input: "  a.b_c-1  ", kind: KindUsername, value: "a.b_c-1"},
		{input: "Ada@Acme.Example", kind: KindEmail, value: "ada@acme.example"},
		{input: "", wantErr: true},
		{input: "ab", wantErr: true},
		{input: strings.Repeat("a", 33), wantErr: true},
		{input: "_ada", wantErr: true},
		{input: "@acme", wantErr: true},
		{input: "ada@", wantErr: true},
		{input: "a@b@c", wantErr: true},
		{input: "a b@c", wantErr: true},
		{input: "+86 138 0013 8000", kind: KindPhone, value: "+8613800138000"},
		{input: "13800138000", kind: KindPhone, value: "+8613800138000"},
		{input: "+1 415 555 2671", kind: KindPhone, value: "+14155552671"},
		{input: "12345", wantErr: true},
		{input: "+999", wantErr: true},
	}
	for _, tt := range tests {
		kind, value, err := NormalizeName(tt.input, "CN")
		if tt.wantErr {
			if !errors.Is(err, ErrInvalidName) {
				t.Errorf("NormalizeName(%q) err = %v", tt.input, err)
			}
			continue
		}
		if err != nil || kind != tt.kind || value != tt.value {
			t.Errorf("NormalizeName(%q) = %q, %q, %v", tt.input, kind, value, err)
		}
	}
}

func TestHasher(t *testing.T) {
	h, err := NewHasher(2)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	hash, err := h.Hash(ctx, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Errorf("hash lacks its parameters: %s", hash)
	}
	if ok, err := h.Verify(ctx, "correct horse", hash); err != nil || !ok {
		t.Errorf("right password: %v, %v", ok, err)
	}
	if ok, err := h.Verify(ctx, "wrong horse", hash); err != nil || ok {
		t.Errorf("wrong password: %v, %v", ok, err)
	}
	if _, err := h.Verify(ctx, "x", "$bcrypt$nope"); err == nil {
		t.Error("foreign hash accepted")
	}
}

func TestHasher_CancelledWhileWaitingForSlot(t *testing.T) {
	h, err := NewHasher(1)
	if err != nil {
		t.Fatal(err)
	}
	h.slots <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Hash(ctx, "password-1234"); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestSigningKey_RoundTripsThroughPEM(t *testing.T) {
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := key.PEM()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSigningKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.KID != key.KID {
		t.Errorf("kid changed: %s != %s", parsed.KID, key.KID)
	}
}

func TestParseSigningKey_RejectsGarbage(t *testing.T) {
	if _, err := ParseSigningKey("not pem"); err == nil {
		t.Error("garbage accepted")
	}
}

func TestJWKS_PublishesNextKey(t *testing.T) {
	current, _ := GenerateSigningKey()
	next, _ := GenerateSigningKey()
	doc := NewKeySet(current, next).JWKS()
	if len(doc.Keys) != 2 || doc.Keys[0].KID != current.KID || doc.Keys[1].KID != next.KID {
		t.Fatalf("keys = %+v", doc.Keys)
	}
	k := doc.Keys[0]
	if k.KTY != "EC" || k.CRV != "P-256" || k.Alg != "ES256" || k.Use != "sig" {
		t.Errorf("jwk = %+v", k)
	}
	if x, err := base64.RawURLEncoding.DecodeString(k.X); err != nil || len(x) != 32 {
		t.Errorf("x = %q, %v", k.X, err)
	}
}

func TestMintAndVerify(t *testing.T) {
	iss := testIssuer(t)
	token, expires, err := iss.MintAccess("usr_1", "ten_acme", "ses_1")
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Until(expires); got > AccessTokenTTL || got < AccessTokenTTL-time.Minute {
		t.Errorf("ttl = %v", got)
	}
	claims, err := iss.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "usr_1" || claims.TenantID != "ten_acme" || claims.SessionID != "ses_1" {
		t.Errorf("claims = %+v", claims)
	}
	if claims.Scope != ScopeAgentUse || claims.ID == "" || claims.IssuedAt == nil {
		t.Errorf("claims = %+v", claims)
	}
}

func TestVerify_Rejects(t *testing.T) {
	iss := testIssuer(t)
	valid, _, err := iss.MintAccess("usr_1", "ten_acme", "ses_1")
	if err != nil {
		t.Fatal(err)
	}

	otherKey := testIssuer(t)
	foreign, _, _ := otherKey.MintAccess("usr_1", "ten_acme", "ses_1")

	assertion, _, _ := iss.SignAssertion("usr_1", "ten_acme", "room:ten_acme__x", time.Minute)

	expired := testIssuer(t)
	expired.keys = iss.keys
	expired.now = func() time.Time { return time.Now().Add(-time.Hour) }
	stale, _, _ := expired.MintAccess("usr_1", "ten_acme", "ses_1")

	wrongIssuer := NewIssuer("http://other", iss.keys)
	misissued, _, _ := wrongIssuer.MintAccess("usr_1", "ten_acme", "ses_1")

	hs256, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iss": iss.url, "aud": AudienceT10}).
		SignedString([]byte(iss.keys.current.x))
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]string{
		"tampered":      valid[:len(valid)-4] + "AAAA",
		"foreign key":   foreign,
		"room audience": assertion,
		"expired":       stale,
		"wrong issuer":  misissued,
		"hmac confused": hs256,
		"empty":         "",
	}
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := iss.Verify(token); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestCheckPassword(t *testing.T) {
	for _, bad := range []string{"short", "password123", "PassWord123", "aaaaaaaaaaaa", "ada@acme.example"} {
		if err := checkPassword(bad, "ada@acme.example"); !errors.Is(err, ErrWeakPassword) {
			t.Errorf("checkPassword(%q) = %v", bad, err)
		}
	}
	if err := checkPassword("change-me-enterprise-admin", "ada@acme.example"); err != nil {
		t.Errorf("good password refused: %v", err)
	}
}

func TestAllowsRedirect(t *testing.T) {
	native := Client{Type: ClientPublic, RedirectURIs: []string{"http://127.0.0.1/callback"}}
	web := Client{Type: ClientConfidential, RedirectURIs: []string{"https://app.example/cb", "http://127.0.0.1/cb"}}
	tests := []struct {
		client Client
		uri    string
		want   bool
	}{
		{native, "http://127.0.0.1/callback", true},
		{native, "http://127.0.0.1:53124/callback", true},
		{native, "http://127.0.0.1:53124/other", false},
		{native, "http://localhost:53124/callback", false},
		{native, "https://127.0.0.1:53124/callback", false},
		{native, "http://127.0.0.1:53124/callback?x=1", false},
		{native, "http://127.0.0.1@evil.example/callback", false},
		{native, "http://evil.example/callback", false},
		{web, "https://app.example/cb", true},
		{web, "https://app.example/cb/", false},
		{web, "https://app.example/cb#x", false},
		{web, "http://127.0.0.1:9/cb", false}, // Any-port applies to public clients only.
	}
	for _, tt := range tests {
		if got := tt.client.AllowsRedirect(tt.uri); got != tt.want {
			t.Errorf("AllowsRedirect(%q) = %v", tt.uri, got)
		}
	}
}

func TestCheckPKCE(t *testing.T) {
	// The example pair from RFC 7636, appendix B.
	verifier, challenge := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if !checkPKCE(verifier, challenge) {
		t.Error("RFC vector refused")
	}
	if checkPKCE(verifier+"x", challenge) || checkPKCE("short", challenge) {
		t.Error("bad verifier accepted")
	}
}

func TestRecoveryCodeNormalization(t *testing.T) {
	code := newRecoveryCode()
	spaced := strings.ToUpper(strings.ReplaceAll(code, "-", " "))
	if string(hashRecoveryCode(code)) != string(hashRecoveryCode(spaced)) {
		t.Errorf("%q and %q hash differently", code, spaced)
	}
}

func TestIPKeyGroupsIPv6ByBlock(t *testing.T) {
	same := [][2]string{
		{"2001:db8:1:2:aaaa::1", "2001:db8:1:2:bbbb::9"},
		{"::ffff:192.0.2.1", "192.0.2.1"},
	}
	for _, pair := range same {
		if ipKey(pair[0]) != ipKey(pair[1]) {
			t.Errorf("%s and %s counted apart", pair[0], pair[1])
		}
	}
	different := [][2]string{
		{"2001:db8:1:2::1", "2001:db8:1:3::1"},
		{"192.0.2.1", "192.0.2.2"},
	}
	for _, pair := range different {
		if ipKey(pair[0]) == ipKey(pair[1]) {
			t.Errorf("%s and %s counted together", pair[0], pair[1])
		}
	}
	if got := ipKey("not-an-ip"); got != "not-an-ip" {
		t.Errorf("ipKey kept %q", got)
	}
}

func TestCheckPasswordCountsCharacters(t *testing.T) {
	for password, weak := range map[string]bool{
		"密码密码密码":                true,
		"密密密密密密密密密密":            true,
		"correct-horse-battery": false,
		"密码是一个很长的不常见句子":         false,
	} {
		if got := checkPassword(password) != nil; got != weak {
			t.Errorf("checkPassword(%q) weak = %v", password, got)
		}
	}
}
