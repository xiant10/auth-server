package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"t10-auth-server/internal/agents"
	"t10-auth-server/internal/db"
	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/identity"
	"t10-auth-server/internal/roles"
)

const (
	testPassword = "change-me-enterprise-admin"
	liveKitKey   = "devkey"
	liveKitSec   = "change-me-to-a-32-plus-character-secret"
)

func TestEveryRouteDeclaresAccess(t *testing.T) {
	s := New(Deps{})
	for _, rt := range s.routes() {
		if rt.access == accessUnset {
			t.Errorf("%s %s has no required access", rt.method, rt.pattern)
		}
		if rt.handler == nil {
			t.Errorf("%s %s has no handler", rt.method, rt.pattern)
		}
	}
}

func TestPublicRoutesAreTheExpectedOnes(t *testing.T) {
	want := map[string]bool{
		"GET /healthz":               true,
		"GET /readyz":                true,
		"GET /.well-known/jwks.json": true,
		"POST /v1/token":             true,
		"POST /v1/revoke":            true,
		"POST /v1/challenges":        true,
		"POST /v1/login":             true,
		"POST /v1/login/mfa":         true,
		"POST /v1/login/register":    true,
		"POST /v1/login/recover":     true,
		"POST /v1/login/pair":        true,
		"POST /v1/login/pair/poll":   true,

		"POST /v1/wechat/signin": true,

		"POST /v1/wechat/refresh": true,

		"POST /v1/wechat/signout": true,
	}
	for _, rt := range New(Deps{}).routes() {
		key := rt.method + " " + rt.pattern
		if rt.access == accessPublic && !want[key] {
			t.Errorf("%s is public", key)
		}
	}
}

func TestGuardPanicsWithoutAccess(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("guard accepted a route with no access")
		}
	}()
	New(Deps{}).guard(route{method: "GET", pattern: "/x"})
}

// The tests below need Postgres. Run them with TEST_DATABASE_URL set; each one
// rebuilds the auth schema there, so never point it at a real database.

type harness struct {
	t    *testing.T
	pool *pgxpool.Pool
	dir  *directory.Service
	id   *identity.Service
	srv  *Server
	url  string
}

var (
	hasherOnce sync.Once
	hasher     *identity.Hasher
)

func newHarness(t *testing.T, devMode bool) *harness {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, "DROP SCHEMA IF EXISTS auth CASCADE"); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	hasherOnce.Do(func() {
		var err error
		if hasher, err = identity.NewHasher(4); err != nil {
			panic(err)
		}
	})
	key, err := identity.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer := identity.NewIssuer("http://localhost:8081", identity.NewKeySet(key, nil))
	dir := directory.NewService(pool)
	ids := identity.NewService(identity.Options{
		Pool: pool, Hasher: hasher, Issuer: issuer, Tenants: dir, Clients: testClients(), Region: "CN",
		TOTPKey: make([]byte, 32), Limits: identity.DefaultLimits(),
	})
	ts := httptest.NewServer(nil)
	t.Cleanup(ts.Close)
	agentService := agents.NewService(pool, dir, issuer, agents.LiveKit{
		URL: "ws://livekit.test:7880", APIKey: liveKitKey, APISecret: liveKitSec,
	}, testRuntimes)
	agentService.AllowExchange([]string{toolGateway})
	agentService.UseToolGateway(true)
	roleService := roles.NewService(pool, testCatalog(t, 1))
	if err := roleService.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	srv := New(Deps{
		Pool:         pool,
		Identity:     ids,
		Directory:    dir,
		Agents:       agentService,
		Roles:        roleService,
		Issuer:       issuer,
		DevMode:      devMode,
		PublicURL:    ts.URL,
		ConsoleURL:   testConsoleURL,
		WorkbenchURL: testWorkbenchURL,
	})
	ts.Config.Handler = srv.Handler()
	for _, name := range []string{voiceRuntime, piRuntime, firingRuntime, gatedRuntime, toolGateway, listedService, otherService} {
		if _, err := ids.AddServiceAccount(ctx, "test", name, serviceSecret(name)); err != nil {
			t.Fatal(err)
		}
	}
	return &harness{t: t, pool: pool, dir: dir, id: ids, srv: srv, url: ts.URL}
}

func (h *harness) tenant(id string) {
	h.t.Helper()
	if _, err := h.dir.Create(context.Background(), "test", id, id); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) user(name string, memberships map[string]string) string {
	h.t.Helper()
	ctx := context.Background()
	var userID string
	err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
		var err error
		userID, err = h.id.CreateUser(ctx, tx, "test", identity.NewUser{Name: name, Password: testPassword})
		if err != nil {
			return err
		}
		for tenant, role := range memberships {
			if _, err := h.dir.AddMember(ctx, tx, "test", tenant, userID, role); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return userID
}

func (h *harness) platformAdmin(userID string) {
	h.t.Helper()
	ctx := context.Background()
	err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
		return h.dir.GrantPlatformAdmin(ctx, tx, "test", userID)
	})
	if err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) do(method, path, bearer string, body any) (int, map[string]any) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, h.url+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (h *harness) login(name, tenant string) string {
	h.t.Helper()
	status, body := h.do("POST", "/v1/token", "", map[string]string{
		"grant_type": "password", "username": name, "password": testPassword, "tenant": tenant,
	})
	if status != http.StatusOK {
		h.t.Fatalf("login %s: %d %v", name, status, body)
	}
	return body["access_token"].(string)
}

func (h *harness) wantStatus(got int, body map[string]any, want int) {
	h.t.Helper()
	if got != want {
		h.t.Fatalf("status = %d, want %d: %v", got, want, body)
	}
}

func (h *harness) auditCount(action, outcome string) int {
	h.t.Helper()
	var n int
	err := h.pool.QueryRow(context.Background(),
		"SELECT count(*) FROM auth.audit_log WHERE action = $1 AND outcome = $2", action, outcome).Scan(&n)
	if err != nil {
		h.t.Fatal(err)
	}
	return n
}

func TestMacClientFlow(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	userID := h.user("ada@acme.example", map[string]string{"ten_acme": directory.RoleMember})

	token := h.login("Ada@Acme.Example", "")
	status, body := h.do("POST", "/v1/rooms/admission", token, map[string]string{"room": "standup", "tenant": "ten_acme"})
	h.wantStatus(status, body, http.StatusOK)

	if body["room_name"] != "ten_acme__standup" {
		t.Errorf("room_name = %v", body["room_name"])
	}
	if body["identity"] != userID || body["server_url"] != "ws://livekit.test:7880" || body["can_publish"] != true {
		t.Errorf("admission = %v", body)
	}
	if body["assertion"] == "" || body["expires_at"] == "" {
		t.Errorf("admission = %v", body)
	}

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(body["room_token"].(string), claims, func(*jwt.Token) (any, error) {
		return []byte(liveKitSec), nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(liveKitKey))
	if err != nil {
		t.Fatalf("room token: %v", err)
	}
	if claims["sub"] != userID {
		t.Errorf("room token sub = %v", claims["sub"])
	}
	video := claims["video"].(map[string]any)
	if video["room"] != "ten_acme__standup" || video["roomJoin"] != true {
		t.Errorf("video grant = %v", video)
	}

	// The assertion must not work as a bearer token.
	status, body = h.do("POST", "/v1/rooms/admission", body["assertion"].(string), map[string]string{"room": "standup"})
	h.wantStatus(status, body, http.StatusUnauthorized)

	if n := h.auditCount("room.admit", "success"); n != 1 {
		t.Errorf("room.admit audit rows = %d", n)
	}
}

func TestPasswordGrantForm(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember})

	form := fmt.Sprintf("grant_type=password&username=ada&password=%s", testPassword)
	resp, err := http.Post(h.url+"/v1/token", "application/x-www-form-urlencoded", strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestPasswordGrantRefusedOutsideDevMode(t *testing.T) {
	h := newHarness(t, false)
	h.tenant("ten_acme")
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember})

	status, body := h.do("POST", "/v1/token", "", map[string]string{
		"grant_type": "password", "username": "ada", "password": testPassword,
	})
	h.wantStatus(status, body, http.StatusBadRequest)
	if body["error"] != "unsupported_grant_type" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestLoginFailuresLookAlike(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	h.user("sus", map[string]string{"ten_acme": directory.RoleMember})
	if _, err := h.pool.Exec(context.Background(),
		"UPDATE auth.users SET status = 'suspended' WHERE id = (SELECT user_id FROM auth.user_identifiers WHERE value = 'sus')"); err != nil {
		t.Fatal(err)
	}

	attempts := []map[string]string{
		{"grant_type": "password", "username": "ada", "password": "wrong-password"},
		{"grant_type": "password", "username": "nobody", "password": testPassword},
		{"grant_type": "password", "username": "!!", "password": testPassword},
		{"grant_type": "password", "username": "sus", "password": testPassword},
	}
	var first map[string]any
	for i, attempt := range attempts {
		status, body := h.do("POST", "/v1/token", "", attempt)
		h.wantStatus(status, body, http.StatusBadRequest)
		if i == 0 {
			first = body
		} else if fmt.Sprint(body) != fmt.Sprint(first) {
			t.Errorf("attempt %d differs: %v vs %v", i, body, first)
		}
	}
	if n := h.auditCount("session.create", "denied"); n != len(attempts) {
		t.Errorf("denied audit rows = %d", n)
	}
}

func TestTenantSelection(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.tenant("ten_other")
	h.tenant("ten_third")
	h.user("multi", map[string]string{"ten_acme": directory.RoleMember, "ten_other": directory.RoleMember})

	status, body := h.do("POST", "/v1/token", "", map[string]string{
		"grant_type": "password", "username": "multi", "password": testPassword,
	})
	h.wantStatus(status, body, http.StatusBadRequest)

	// A tenant named by the client is not authorization.
	status, body = h.do("POST", "/v1/token", "", map[string]string{
		"grant_type": "password", "username": "multi", "password": testPassword, "tenant": "ten_third",
	})
	h.wantStatus(status, body, http.StatusForbidden)

	token := h.login("multi", "ten_other")
	status, body = h.do("POST", "/v1/rooms/admission", token, map[string]string{"room": "r"})
	h.wantStatus(status, body, http.StatusOK)
	if body["room_name"] != "ten_other__r" {
		t.Errorf("room_name = %v", body["room_name"])
	}
}

func TestAdmissionRefusals(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.tenant("ten_other")
	h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
	token := h.login("ada", "")

	status, body := h.do("POST", "/v1/rooms/admission", "", map[string]string{"room": "r"})
	h.wantStatus(status, body, http.StatusUnauthorized)

	status, body = h.do("POST", "/v1/rooms/admission", token, map[string]string{"room": "r", "tenant": "ten_other"})
	h.wantStatus(status, body, http.StatusForbidden)

	status, body = h.do("POST", "/v1/rooms/admission", token, map[string]string{"room": "../etc"})
	h.wantStatus(status, body, http.StatusBadRequest)

	status, body = h.do("POST", "/v1/rooms/admission", token, map[string]string{"room": ""})
	h.wantStatus(status, body, http.StatusBadRequest)
}

func TestSuspensionsStopAdmissionWhileTokenIsValid(t *testing.T) {
	ctx := context.Background()

	t.Run("tenant", func(t *testing.T) {
		h := newHarness(t, true)
		h.tenant("ten_acme")
		h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
		token := h.login("ada", "")
		if err := h.dir.SetTenantStatus(ctx, "test", "ten_acme", directory.TenantSuspended); err != nil {
			t.Fatal(err)
		}
		status, body := h.do("POST", "/v1/rooms/admission", token, map[string]string{"room": "r"})
		h.wantStatus(status, body, http.StatusForbidden)
	})

	t.Run("membership", func(t *testing.T) {
		h := newHarness(t, true)
		h.tenant("ten_acme")
		userID := h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
		token := h.login("ada", "")
		inactive := directory.MemberInactive
		if _, err := h.dir.UpdateMember(ctx, "test", "ten_acme", userID, directory.MemberUpdate{Status: &inactive}); err != nil {
			t.Fatal(err)
		}
		status, body := h.do("POST", "/v1/rooms/admission", token, map[string]string{"room": "r"})
		h.wantStatus(status, body, http.StatusForbidden)
	})

	t.Run("revoked session", func(t *testing.T) {
		h := newHarness(t, true)
		h.tenant("ten_acme")
		h.user("ada", map[string]string{"ten_acme": directory.RoleMember})
		token := h.login("ada", "")
		if _, err := h.pool.Exec(ctx, "UPDATE auth.sessions SET revoked_at = now()"); err != nil {
			t.Fatal(err)
		}
		status, body := h.do("POST", "/v1/rooms/admission", token, map[string]string{"room": "r"})
		h.wantStatus(status, body, http.StatusUnauthorized)
	})
}

func TestTenantAdministration(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	h.tenant("ten_other")
	root := h.user("root", nil)
	h.platformAdmin(root)
	h.user("boss", map[string]string{"ten_acme": directory.RoleAdmin})
	h.user("worker", map[string]string{"ten_acme": directory.RoleMember})
	newcomer := h.user("newcomer", nil)
	h.user("outsider", map[string]string{"ten_other": directory.RoleAdmin})

	rootToken := h.login("root", "") // No membership, so no tenant on the token.
	bossToken := h.login("boss", "")
	workerToken := h.login("worker", "")
	outsiderToken := h.login("outsider", "")

	// A platform admin creates tenants; nobody else can.
	status, body := h.do("POST", "/v1/tenants", rootToken, map[string]string{"id": "ten_new", "name": "New"})
	h.wantStatus(status, body, http.StatusCreated)
	status, body = h.do("POST", "/v1/tenants", bossToken, map[string]string{"name": "Nope"})
	h.wantStatus(status, body, http.StatusForbidden)
	status, body = h.do("POST", "/v1/tenants", rootToken, map[string]string{"id": "ten_new", "name": "Again"})
	h.wantStatus(status, body, http.StatusConflict)
	status, body = h.do("POST", "/v1/tenants", rootToken, map[string]string{"id": "ten_a__b", "name": "Bad"})
	h.wantStatus(status, body, http.StatusBadRequest)

	// Adding an existing user by ID is a platform action; tenants invite.
	status, body = h.do("POST", "/v1/tenants/ten_acme/members", bossToken, map[string]string{"user_id": newcomer})
	h.wantStatus(status, body, http.StatusForbidden)
	status, body = h.do("POST", "/v1/tenants/ten_acme/members", rootToken, map[string]string{"user_id": newcomer})
	h.wantStatus(status, body, http.StatusCreated)

	// A tenant admin manages their own tenant only.
	status, body = h.do("GET", "/v1/tenants/ten_acme/members", bossToken, nil)
	h.wantStatus(status, body, http.StatusOK)
	if n := len(body["members"].([]any)); n != 3 {
		t.Errorf("members = %d", n)
	}
	status, body = h.do("GET", "/v1/tenants/ten_acme/members", workerToken, nil)
	h.wantStatus(status, body, http.StatusForbidden)
	status, body = h.do("GET", "/v1/tenants/ten_acme/members", outsiderToken, nil)
	h.wantStatus(status, body, http.StatusForbidden)
	status, body = h.do("POST", "/v1/tenants/ten_acme/members", rootToken, map[string]string{"user_id": "usr_missing"})
	h.wantStatus(status, body, http.StatusNotFound)
	status, body = h.do("POST", "/v1/tenants/ten_acme/members", rootToken, map[string]string{"user_id": newcomer, "role": "member"})
	h.wantStatus(status, body, http.StatusConflict)
	status, body = h.do("PATCH", "/v1/tenants/ten_acme/members/"+newcomer, bossToken, map[string]string{"role": "owner"})
	h.wantStatus(status, body, http.StatusBadRequest)
	status, body = h.do("PATCH", "/v1/tenants/ten_acme/members/"+newcomer, bossToken, map[string]string{"role": "admin"})
	h.wantStatus(status, body, http.StatusOK)

	// A tenant admin cannot suspend tenants, even their own.
	status, body = h.do("POST", "/v1/tenants/ten_acme/suspend", bossToken, nil)
	h.wantStatus(status, body, http.StatusForbidden)
	status, body = h.do("POST", "/v1/tenants/ten_acme/suspend", rootToken, nil)
	h.wantStatus(status, body, http.StatusOK)

	// Suspension takes the tenant admin's rights with it, and reactivating restores them.
	status, body = h.do("GET", "/v1/tenants/ten_acme", bossToken, nil)
	h.wantStatus(status, body, http.StatusForbidden)
	status, body = h.do("POST", "/v1/tenants/ten_acme/activate", rootToken, nil)
	h.wantStatus(status, body, http.StatusOK)
	status, body = h.do("GET", "/v1/tenants/ten_acme", bossToken, nil)
	h.wantStatus(status, body, http.StatusOK)

	if h.auditCount("tenant.suspended", "success") != 1 || h.auditCount("membership.update", "success") != 1 {
		t.Error("tenant changes are missing audit rows")
	}
	var denied int
	if err := h.pool.QueryRow(context.Background(),
		"SELECT count(*) FROM auth.audit_log WHERE outcome = 'denied' AND action LIKE 'http.%'").Scan(&denied); err != nil {
		t.Fatal(err)
	}
	if denied == 0 {
		t.Error("denied requests left no audit rows")
	}
}

func TestPlatformAdminGetsNoTenantAccess(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	root := h.user("root", nil)
	h.platformAdmin(root)

	status, body := h.do("POST", "/v1/rooms/admission", h.login("root", ""), map[string]string{"room": "r", "tenant": "ten_acme"})
	h.wantStatus(status, body, http.StatusForbidden)
}

func TestAuditLogIsAppendOnly(t *testing.T) {
	h := newHarness(t, true)
	h.tenant("ten_acme")
	ctx := context.Background()
	for _, stmt := range []string{
		"UPDATE auth.audit_log SET actor = 'x'",
		"DELETE FROM auth.audit_log",
		"TRUNCATE auth.audit_log",
	} {
		if _, err := h.pool.Exec(ctx, stmt); err == nil {
			t.Errorf("%s succeeded", stmt)
		}
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	h := newHarness(t, true)
	if err := db.Migrate(context.Background(), h.pool); err != nil {
		t.Fatal(err)
	}
}

func TestJWKS(t *testing.T) {
	h := newHarness(t, true)
	status, body := h.do("GET", "/.well-known/jwks.json", "", nil)
	h.wantStatus(status, body, http.StatusOK)
	keys := body["keys"].([]any)
	if len(keys) != 1 || keys[0].(map[string]any)["alg"] != "ES256" {
		t.Errorf("keys = %v", keys)
	}
}
