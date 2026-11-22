package main

// The demo's start links: an outreach email carries a signed link, and the
// prospect's tenant, with a cast of teammates, is made only when they open it
// and press Start. Opening the link changes nothing, because mail scanners
// open every link in a message. Demo only: it runs where DEMO_START_KEY is set.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"auth-server/internal/directory"
	"auth-server/internal/identity"
)

// demoClaim is what a start link carries.
type demoClaim struct {
	Tenant  string `json:"t"`
	Company string `json:"c"`
	Name    string `json:"n"`
	Expires int64  `json:"e"`
}

var demoTenantPattern = regexp.MustCompile(`^ten_[a-z0-9-]+$`)

func signClaim(key []byte, c demoClaim) string {
	payload, _ := json.Marshal(c)
	body := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

var errBadLink = errors.New("this link isn't valid")

func verifyClaim(key []byte, token string, now time.Time) (demoClaim, error) {
	body, sig, ok := strings.Cut(token, ".")
	if !ok {
		return demoClaim{}, errBadLink
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return demoClaim{}, errBadLink
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(body))
	if !hmac.Equal(got, mac.Sum(nil)) {
		return demoClaim{}, errBadLink
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return demoClaim{}, errBadLink
	}
	var c demoClaim
	if json.Unmarshal(payload, &c) != nil || !demoTenantPattern.MatchString(c.Tenant) || c.Company == "" {
		return demoClaim{}, errBadLink
	}
	if now.Unix() > c.Expires {
		return c, errors.New("this link has expired")
	}
	return c, nil
}

func demoKey() ([]byte, error) {
	key := os.Getenv("DEMO_START_KEY")
	if len(key) < 32 {
		return nil, errors.New("DEMO_START_KEY must be set, 32 characters or more")
	}
	return []byte(key), nil
}

// demoLink prints a start link. It needs no database.
func demoLink(args []string) error {
	fs := flag.NewFlagSet("demo-link", flag.ExitOnError)
	tenantID := fs.String("tenant-id", "", "the tenant it will make, such as ten_contoso-x7k2")
	company := fs.String("company", "", "the prospect's company, the tenant's name")
	name := fs.String("name", "", "the prospect's name, for the greeting")
	days := fs.Int("days", 30, "how long the link can be started")
	publicURL := fs.String("public-url", os.Getenv("AUTH_PUBLIC_URL"), "auth-server's public URL; default AUTH_PUBLIC_URL")
	fs.Parse(args)
	if !demoTenantPattern.MatchString(*tenantID) || *company == "" || *publicURL == "" || *days < 1 {
		return errors.New("demo-link needs --tenant-id (ten_ and lowercase letters, digits, -), --company, --public-url and --days of 1 or more")
	}
	key, err := demoKey()
	if err != nil {
		return err
	}
	c := demoClaim{Tenant: *tenantID, Company: *company, Name: *name, Expires: time.Now().Add(time.Duration(*days) * 24 * time.Hour).Unix()}
	fmt.Printf("%s/demo/start?t=%s\n", strings.TrimRight(*publicURL, "/"), signClaim(key, c))
	return nil
}

// castMember is a teammate every prospect's tenant starts with.
type castMember struct{ Name, Job string }

// defaultCast matches the demo's tenant Acme, less its admin: the prospect is that.
var defaultCast = []castMember{{"bob", "Sales"}, {"carol", "Support"}, {"dave", "Finance"}, {"erin", "Engineering"}, {"frank", "Facilities"}}

type teammateLogin struct{ SignIn, Password, Job string }

// demoStarter makes a prospect's tenant from a start link.
type demoStarter struct {
	pool                    *pgxpool.Pool
	dir                     *directory.Service
	ids                     *identity.Service
	key                     []byte
	publicURL, workbenchURL string
	// domain makes teammates' sign-in names: bob@<tenant>.<domain>.
	domain string
	cast   []castMember
	now    func() time.Time
}

type startState int

const (
	// startNew made the tenant and its teammates now.
	startNew startState = iota
	// startPending found the tenant without its admin: the prospect started
	// but didn't finish making their account.
	startPending
	// startReady found the prospect's account made: they sign in.
	startReady
	// startEnded found the tenant suspended.
	startEnded
)

type startResult struct {
	state     startState
	register  string
	teammates []teammateLogin
}

func (d *demoStarter) start(ctx context.Context, c demoClaim) (startResult, error) {
	t, err := d.dir.GetTenant(ctx, c.Tenant)
	if errors.Is(err, directory.ErrNotFound) {
		var teammates []teammateLogin
		teammates, err = d.create(ctx, c)
		if err == nil {
			register, err := d.invite(ctx, c.Tenant)
			return startResult{state: startNew, register: register, teammates: teammates}, err
		}
		// Pressed twice at once: the other press made it.
		if t, err = d.dir.GetTenant(ctx, c.Tenant); err != nil {
			return startResult{}, err
		}
	} else if err != nil {
		return startResult{}, err
	}
	if t.Status != directory.TenantActive {
		return startResult{state: startEnded}, nil
	}
	var hasAdmin bool
	if err := d.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.memberships WHERE tenant_id = $1 AND role = $2 AND status = 'active')`,
		c.Tenant, directory.RoleAdmin).Scan(&hasAdmin); err != nil {
		return startResult{}, err
	}
	if hasAdmin {
		return startResult{state: startReady}, nil
	}
	register, err := d.invite(ctx, c.Tenant)
	return startResult{state: startPending, register: register}, err
}

// create makes the tenant and its teammates in one transaction, so a failure
// leaves nothing half made.
func (d *demoStarter) create(ctx context.Context, c demoClaim) ([]teammateLogin, error) {
	var logins []teammateLogin
	err := pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		if _, err := d.dir.CreateTenant(ctx, tx, actor, c.Tenant, c.Company); err != nil {
			return err
		}
		host := strings.TrimPrefix(c.Tenant, "ten_") + "." + d.domain
		for _, m := range d.cast {
			login := teammateLogin{SignIn: m.Name + "@" + host, Password: demoPassword(), Job: m.Job}
			display := strings.ToUpper(m.Name[:1]) + m.Name[1:]
			userID, err := d.ids.CreateUser(ctx, tx, actor, identity.NewUser{Name: login.SignIn, Password: login.Password, DisplayName: display})
			if err != nil {
				return fmt.Errorf("teammate %s: %w", m.Name, err)
			}
			if _, err := d.dir.AddMember(ctx, tx, actor, c.Tenant, userID, directory.RoleMember); err != nil {
				return err
			}
			logins = append(logins, login)
		}
		return nil
	})
	return logins, err
}

func (d *demoStarter) invite(ctx context.Context, tenant string) (string, error) {
	token, err := d.dir.CreateInvitation(ctx, actor, tenant, directory.RoleAdmin)
	if err != nil {
		return "", err
	}
	// After the recovery codes, / sends them into their tenant in the workbench.
	return d.publicURL + "/v1/register?invite=" + token + "&next=%2F", nil
}

// demoPassword is 14 characters that read aloud and type without confusion.
func demoPassword() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	b := make([]byte, 14)
	rand.Read(b) // Never fails; see crypto/rand.
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b[:4]) + "-" + string(b[4:9]) + "-" + string(b[9:])
}

var demoPage = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>Your t10 demo</title>
<style>
:root{color-scheme:light dark;--bg:#f7f7f5;--fg:#1d1d1b;--muted:#6b6b66;--card:#fff;--line:#e3e3de;--accent:#2f5bd3}
@media (prefers-color-scheme:dark){:root{--bg:#161614;--fg:#ececea;--muted:#9a9a94;--card:#1f1f1d;--line:#33332f;--accent:#7c9cf0}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,sans-serif}
main{max-width:560px;margin:8vh auto;padding:0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:28px}
h1{font-size:1.4rem;margin:0 0 12px}p{margin:0 0 14px}.muted{color:var(--muted);font-size:.92rem}
button,.button{display:inline-block;background:var(--accent);color:#fff;border:0;border-radius:8px;padding:11px 20px;font:inherit;font-weight:600;cursor:pointer;text-decoration:none}
table{width:100%;border-collapse:collapse;margin:8px 0 18px;font-size:.92rem}
td{padding:6px 4px;border-top:1px solid var(--line);vertical-align:top}code{font-size:.9rem;word-break:break-all}
</style></head><body><main><div class="card">
{{if eq .Page "offer"}}
<h1>{{if .Name}}Hi {{.Name}}, your{{else}}Your{{end}} t10 demo for {{.Company}}</h1>
<p>Press Start to set up a workspace for {{.Company}}, with five teammates already in it. Then make your own account: you'll be its administrator.</p>
<form method="post" action="/demo/start"><input type="hidden" name="t" value="{{.Token}}"><button type="submit">Start the demo</button></form>
<p class="muted" style="margin-top:16px">Nothing is set up until you press Start.</p>
{{else if eq .Page "new"}}
<h1>{{.Company}} is ready</h1>
<p>These teammates are in your workspace. Save their sign-ins now: they aren't shown again. Sign in as one in another browser to see a task you give them from their side.</p>
<table>{{range .Teammates}}<tr><td>{{.Job}}</td><td><code>{{.SignIn}}</code></td><td><code>{{.Password}}</code></td></tr>{{end}}</table>
<p><a class="button" href="{{.Register}}">Make your account</a></p>
<p class="muted">Lost one? As administrator you can make a new sign-in link for any teammate under Members.</p>
{{else if eq .Page "ended"}}
<h1>This demo has ended</h1><p>Reply to the email that brought you here if you'd like to keep going.</p>
{{else}}
<h1>{{.Title}}</h1><p>{{.Message}}</p>
{{if .Link}}<p><a class="button" href="{{.Link}}">{{.LinkText}}</a></p>{{end}}
{{end}}
</div></main></body></html>`))

type demoPageData struct {
	Page, Name, Company, Token, Register, Title, Message, Link, LinkText string
	Teammates                                                            []teammateLogin
}

func (d *demoStarter) render(w http.ResponseWriter, status int, data demoPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
	if err := demoPage.Execute(w, data); err != nil {
		slog.Error("demo page", "error", err)
	}
}

func (d *demoStarter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/demo/start" {
		http.NotFound(w, r)
		return
	}
	token := r.FormValue("t")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c, err := verifyClaim(d.key, token, d.now())
	if err != nil {
		d.render(w, http.StatusBadRequest, demoPageData{Title: "This link doesn't work", Message: err.Error() + ". Reply to the email that brought you here for a new one."})
		return
	}
	if r.Method == http.MethodGet {
		d.render(w, http.StatusOK, demoPageData{Page: "offer", Name: c.Name, Company: c.Company, Token: token})
		return
	}
	res, err := d.start(r.Context(), c)
	if err != nil {
		slog.Error("demo start", "tenant", c.Tenant, "error", err)
		d.render(w, http.StatusInternalServerError, demoPageData{Title: "Something went wrong", Message: "The demo couldn't be set up. Try again in a minute."})
		return
	}
	slog.Info("demo start", "tenant", c.Tenant, "state", res.state)
	switch res.state {
	case startNew:
		d.render(w, http.StatusOK, demoPageData{Page: "new", Company: c.Company, Register: res.register, Teammates: res.teammates})
	case startPending:
		http.Redirect(w, r, res.register, http.StatusSeeOther)
	case startReady:
		d.render(w, http.StatusOK, demoPageData{Title: c.Company + " is already set up", Message: "Sign in with the account you made.",
			Link: d.workbenchURL + "/", LinkText: "Sign in"})
	case startEnded:
		d.render(w, http.StatusGone, demoPageData{Page: "ended"})
	}
}

// demoStart serves the start links.
func demoStart(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("demo-start", flag.ExitOnError)
	listen := fs.String("listen", ":8090", "address to serve on")
	domain := fs.String("domain", "", "teammates sign in as bob@<tenant>.<domain>")
	publicURL := fs.String("public-url", os.Getenv("AUTH_PUBLIC_URL"), "auth-server's public URL; default AUTH_PUBLIC_URL")
	workbenchURL := fs.String("workbench-url", os.Getenv("AUTH_WORKBENCH_URL"), "the workbench's URL; default AUTH_WORKBENCH_URL")
	fs.Parse(args)
	if *domain == "" || *publicURL == "" || *workbenchURL == "" {
		return errors.New("demo-start needs --domain, --public-url and --workbench-url")
	}
	key, err := demoKey()
	if err != nil {
		return err
	}
	pool, err := open(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	dir := directory.NewService(pool)
	ids, err := newIdentity(pool, dir)
	if err != nil {
		return err
	}
	d := &demoStarter{pool: pool, dir: dir, ids: ids, key: key, domain: *domain, cast: defaultCast, now: time.Now,
		publicURL: strings.TrimRight(*publicURL, "/"), workbenchURL: strings.TrimRight(*workbenchURL, "/")}
	srv := &http.Server{Addr: *listen, Handler: d, ReadHeaderTimeout: 10 * time.Second}
	slog.Info("demo start links", "listen", *listen)
	return srv.ListenAndServe()
}
