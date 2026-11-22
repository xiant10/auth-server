package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"auth-server/internal/directory"
	"auth-server/internal/identity"
)

var testDemoKey = []byte("a-demo-start-key-of-32-characters!")

func TestStartLinksAreSignedAndExpire(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := demoClaim{Tenant: "ten_contoso-x7k2", Company: "Contoso", Name: "Jane", Expires: now.Add(time.Hour).Unix()}
	token := signClaim(testDemoKey, c)
	if got, err := verifyClaim(testDemoKey, token, now); err != nil || got != c {
		t.Fatalf("verify: %+v %v", got, err)
	}
	if _, err := verifyClaim([]byte("another-key-another-key-another-key"), token, now); err == nil {
		t.Error("a link signed with another key was accepted")
	}
	body, sig, _ := strings.Cut(token, ".")
	forged := signClaim([]byte("x"), demoClaim{Tenant: "ten_acme", Company: "Acme", Expires: c.Expires})
	fbody, _, _ := strings.Cut(forged, ".")
	if _, err := verifyClaim(testDemoKey, fbody+"."+sig, now); err == nil {
		t.Error("a changed claim kept its signature")
	}
	if _, err := verifyClaim(testDemoKey, body, now); err == nil {
		t.Error("a link without a signature was accepted")
	}
	if _, err := verifyClaim(testDemoKey, token, now.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("an expired link: %v", err)
	}
	bad := signClaim(testDemoKey, demoClaim{Tenant: "ten_Acme Corp", Company: "x", Expires: c.Expires})
	if _, err := verifyClaim(testDemoKey, bad, now); err == nil {
		t.Error("a tenant ID the database refuses was accepted")
	}
}

func TestDemoPasswordsPassTheRules(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		p := demoPassword()
		if len(p) != 16 || seen[p] {
			t.Fatalf("password %q", p)
		}
		seen[p] = true
	}
}

// Opening a link makes nothing; Start makes the tenant and its teammates once,
// then sends the prospect to make their account, and later visits find it.
func TestStartMakesTheTenantOnlyOnStart(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	dir := directory.NewService(pool)
	ids, err := newIdentity(pool, dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	d := &demoStarter{pool: pool, dir: dir, ids: ids, key: testDemoKey, domain: "demo.example", cast: defaultCast,
		publicURL: "https://t10-auth.demo.example", workbenchURL: "https://t10-workbench.demo.example", now: func() time.Time { return now }}
	server := httptest.NewServer(d)
	defer server.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	token := signClaim(testDemoKey, demoClaim{Tenant: "ten_contoso-x7k2", Company: "Contoso", Name: "Jane <b>", Expires: now.Add(time.Hour).Unix()})

	get := func() string {
		t.Helper()
		resp, err := client.Get(server.URL + "/demo/start?t=" + url.QueryEscape(token))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET: %d", resp.StatusCode)
		}
		return string(b)
	}
	post := func() (*http.Response, string) {
		t.Helper()
		resp, err := client.PostForm(server.URL+"/demo/start", url.Values{"t": {token}})
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}

	page := get()
	if !strings.Contains(page, "Contoso") || strings.Contains(page, "<b>") || !strings.Contains(page, `method="post"`) {
		t.Fatalf("offer page: %s", page)
	}
	get()
	if _, err := dir.GetTenant(ctx, "ten_contoso-x7k2"); err == nil {
		t.Fatal("opening the link made the tenant")
	}

	resp, page := post()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("start: %d %s", resp.StatusCode, page)
	}
	logins := regexp.MustCompile(`<code>([a-z]+@contoso-x7k2\.demo\.example)</code></td><td><code>([a-z0-9-]+)</code>`).FindAllStringSubmatch(page, -1)
	if len(logins) != len(defaultCast) {
		t.Fatalf("%d teammates shown: %s", len(logins), page)
	}
	// Sign in as the server does, with its limits; authctl's service has none.
	hasher, _ := identity.NewHasher(1)
	signIn := identity.NewService(identity.Options{Pool: pool, Hasher: hasher, Tenants: dir, Region: "CN", Limits: identity.DefaultLimits()})
	for _, l := range logins {
		if _, _, err := signIn.VerifyCredentials(ctx, l[1], l[2], "", "127.0.0.1"); err != nil {
			t.Errorf("teammate %s can't sign in: %v", l[1], err)
		}
	}
	register := regexp.MustCompile(`href="(https://t10-auth\.demo\.example/v1/register\?invite=[^"]+)"`).FindStringSubmatch(page)
	if register == nil {
		t.Fatalf("no register link: %s", page)
	}
	var members, admins int
	pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE role = 'admin') FROM auth.memberships WHERE tenant_id = 'ten_contoso-x7k2'`).Scan(&members, &admins)
	if members != len(defaultCast) || admins != 0 {
		t.Fatalf("%d members, %d admins", members, admins)
	}

	// Pressed again before making an account: a fresh invitation, no new teammates.
	resp, _ = post()
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "https://t10-auth.demo.example/v1/register?invite=") {
		t.Fatalf("pending: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	pool.QueryRow(ctx, `SELECT count(*) FROM auth.memberships WHERE tenant_id = 'ten_contoso-x7k2'`).Scan(&members)
	if members != len(defaultCast) {
		t.Fatalf("a second Start added teammates: %d", members)
	}

	// Once the prospect's account is made, Start sends them to sign in.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	userID, err := ids.CreateUser(ctx, tx, "test", identity.NewUser{Name: "jane@contoso.example", Password: "a-long-password-1"})
	if err == nil {
		_, err = dir.AddMember(ctx, tx, "test", "ten_contoso-x7k2", userID, directory.RoleAdmin)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	resp, page = post()
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "already set up") || !strings.Contains(page, "https://t10-workbench.demo.example/") {
		t.Fatalf("ready: %d %s", resp.StatusCode, page)
	}

	if err := dir.SetTenantStatus(ctx, "test", "ten_contoso-x7k2", directory.TenantSuspended); err != nil {
		t.Fatal(err)
	}
	if resp, page = post(); resp.StatusCode != http.StatusGone || !strings.Contains(page, "ended") {
		t.Fatalf("ended: %d %s", resp.StatusCode, page)
	}

	// A bad link makes nothing.
	resp, err = client.PostForm(server.URL+"/demo/start", url.Values{"t": {"nope"}})
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad link: %v %v", resp, err)
	}
	resp.Body.Close()
}

// A tenant ended before it was started can't be started.
func TestAnEndedLinkCantStart(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	dir := directory.NewService(pool)
	ids, _ := newIdentity(pool, dir)
	d := &demoStarter{pool: pool, dir: dir, ids: ids, key: testDemoKey, domain: "demo.example", cast: defaultCast, now: time.Now}
	var out strings.Builder
	if err := addTenant(ctx, pool, &out, "ten_globex-a1b2", "Globex", false); err != nil {
		t.Fatal(err)
	}
	if err := dir.SetTenantStatus(ctx, "test", "ten_globex-a1b2", directory.TenantSuspended); err != nil {
		t.Fatal(err)
	}
	res, err := d.start(ctx, demoClaim{Tenant: "ten_globex-a1b2", Company: "Globex", Expires: time.Now().Add(time.Hour).Unix()})
	if err != nil || res.state != startEnded {
		t.Fatalf("%+v %v", res, err)
	}
}
