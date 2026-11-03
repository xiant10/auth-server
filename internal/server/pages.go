package server

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	qrcode "github.com/skip2/go-qrcode"

	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/identity"
)

//go:embed pages.html
var pagesHTML string

//go:embed logo.png
var logoBytes []byte

var logoDataURL = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(logoBytes))

// pages is the English set, and pagesZH its copy for Chinese. A set's t function
// is fixed when it is built, so no template passes the language around.
var pages = template.Must(template.New("pages").Funcs(template.FuncMap{
	"logo": func() template.URL { return logoDataURL },
}).Funcs(translator(langEN)).Parse(pagesHTML))

var pagesZH = template.Must(pages.Clone()).Funcs(translator(langZH))

const defaultNext = "/v1/account"

type pageData struct {
	Title, Error, Notice string
	Next, Invite, Token  string
	Nonce                string
	// Here is the address the language switch returns to. Empty hides the switch.
	Here       string
	Open       bool
	Codes      []string
	Account    identity.Account
	Enrollment identity.TOTPEnrollment
	// TOTPLink is marked safe because html/template blanks any otpauth: URL. The
	// OTP library builds it, and escapes the one user-supplied part.
	TOTPLink template.URL
	// TOTPImage is a data: URL, which html/template also blanks. It is this
	// service's own PNG.
	TOTPImage template.URL
	// ConsoleURL and OrgURL are where this person administers the platform and
	// their tenants, empty if they don't. Wide gives the account page room.
	ConsoleURL, OrgURL string
	Wide               bool
}

func setPageHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	// form-action stays unset on purpose: browsers apply it to redirects after
	// a post, which would block the code flow's redirect to the client.
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; frame-ancestors 'none'")
	// same-origin, not no-referrer: under no-referrer browsers send "Origin: null"
	// on form posts, which sameOrigin would refuse. Tokens in URLs still stay
	// out of cross-site requests.
	h.Set("Referrer-Policy", "same-origin")
	h.Set("X-Content-Type-Options", "nosniff")
}

// render answers in the viewer's language. A page reached by GET offers the
// language switch, which returns to the same address. An answer to a post offers
// it only if it sets Here, because some of those show a secret just once.
func render(w http.ResponseWriter, r *http.Request, status int, name string, data pageData) {
	lang := requestLang(r)
	data.Title, data.Error, data.Notice = translate(lang, data.Title), translate(lang, data.Error), translate(lang, data.Notice)
	if data.Here == "" && r.Method == http.MethodGet {
		data.Here = r.URL.RequestURI()
	}
	execute(w, r, pagesFor(lang), status, name, data)
}

func execute(w http.ResponseWriter, r *http.Request, set *template.Template, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := set.ExecuteTemplate(w, name, data); err != nil {
		slog.ErrorContext(r.Context(), "render page", "page", name, "error", err)
	}
}

// sameOrigin requires an Origin header matching the public URL, so another site
// cannot post to these pages with the user's cookie.
func (s *Server) sameOrigin(r *http.Request) bool {
	return r.Header.Get("Origin") == s.PublicURL
}

// The __Host- prefix needs https, so a localhost dev server uses a plain name.
func (s *Server) cookieName() string {
	if s.secureCookies() {
		return "__Host-t10_session"
	}
	return "t10_session"
}

func (s *Server) secureCookies() bool {
	return strings.HasPrefix(s.PublicURL, "https://")
}

func (s *Server) setSessionCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.secureCookies(), SameSite: http.SameSiteLaxMode,
	})
}

// browserPrincipal resolves the session cookie. A missing or dead cookie is
// not an error; it means the user is signed out.
func (s *Server) browserPrincipal(r *http.Request) (identity.Principal, bool, error) {
	cookie, err := r.Cookie(s.cookieName())
	if err != nil {
		return identity.Principal{}, false, nil
	}
	p, err := s.Identity.BrowserSession(r.Context(), cookie.Value)
	if errors.Is(err, identity.ErrInvalidToken) {
		return identity.Principal{}, false, nil
	}
	if err != nil {
		return identity.Principal{}, false, err
	}
	return p, true, nil
}

// safeNext keeps a post-sign-in redirect on this service's own pages, so a
// crafted link cannot send the user elsewhere.
func safeNext(next string) string {
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || strings.ContainsAny(next, "\\\r\n") {
		return defaultNext
	}
	switch u.Path {
	case "/v1/authorize", "/v1/join", "/v1/account", "/admin":
		return next
	}
	return defaultNext
}

// languageNext is safeNext plus the signed-out pages. Signing in can't lead to
// those, but choosing a language on one has to return to it.
func languageNext(next string) string {
	u, err := url.Parse(next)
	if err == nil && u.Scheme == "" && u.Host == "" && !strings.ContainsAny(next, "\\\r\n") {
		switch u.Path {
		case "/v1/signin", "/v1/register", "/v1/recover", "/v1/reset":
			return next
		}
	}
	return safeNext(next)
}

func (s *Server) handleLanguage(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	if lang := r.PostFormValue("lang"); validLang(lang) {
		http.SetCookie(w, &http.Cookie{
			Name: langCookie, Value: lang, Path: "/", MaxAge: langCookieAge,
			HttpOnly: true, Secure: s.secureCookies(), SameSite: http.SameSiteLaxMode,
		})
	}
	http.Redirect(w, r, languageNext(r.PostFormValue("next")), http.StatusSeeOther)
}

// handleAuthorize starts the code flow. A bad client or redirect URI gets an
// error page, because redirecting would send it to an unvetted address.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	q := r.URL.Query()
	clientID, redirectURI := q.Get("client_id"), q.Get("redirect_uri")
	client, ok := s.Identity.Client(clientID)
	if !ok || !client.AllowsRedirect(redirectURI) {
		render(w, r, http.StatusBadRequest, "problem", pageData{Title: "Sign-in failed", Error: "Unknown client or redirect address."})
		return
	}
	redirect := func(params url.Values) {
		if state := q.Get("state"); state != "" {
			params.Set("state", state)
		}
		target, _ := url.Parse(redirectURI)
		target.RawQuery = params.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	}
	challenge := q.Get("code_challenge")
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || len(challenge) != 43 {
		redirect(url.Values{"error": {"invalid_request"}})
		return
	}

	p, ok, err := s.browserPrincipal(r)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	if !ok {
		http.Redirect(w, r, "/v1/signin?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	code, err := s.Identity.IssueCode(r.Context(), p.SessionID, clientID, redirectURI, challenge)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	redirect(url.Values{"code": {code}})
}

func (s *Server) handleSignInPage(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	notice := ""
	switch r.URL.Query().Get("reason") {
	case "stepup":
		notice = "Sign in again to confirm it's you. Platform actions need an authenticator code from the last 15 minutes."
	case "signedout":
		notice = "You're signed out."
	}
	s.renderSignIn(w, r, http.StatusOK, safeNext(r.URL.Query().Get("next")), "", notice)
}

// newNonce returns a value for a page's script-src.
func newNonce() string {
	nonce := make([]byte, 16)
	rand.Read(nonce) // Never fails; see crypto/rand.
	return base64.RawStdEncoding.EncodeToString(nonce)
}

// renderSignIn allows one script, by nonce, and images from data URIs: the
// sign-in page alone needs them, to show and poll a QR code.
func (s *Server) renderSignIn(w http.ResponseWriter, r *http.Request, status int, next, problem, notice string) {
	encoded := newNonce()
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; script-src 'nonce-"+encoded+"'")
	render(w, r, status, "signin", pageData{
		Title: "Sign in", Next: next, Error: problem, Notice: notice, Nonce: encoded,
		Here: "/v1/signin?next=" + url.QueryEscape(next),
	})
}

func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	next := safeNext(r.PostFormValue("next"))
	userID, mfa, err := s.Identity.VerifyCredentials(r.Context(),
		r.PostFormValue("name"), r.PostFormValue("password"), r.PostFormValue("code"), s.clientIP(r))
	if msg, status := signInProblem(err); msg != "" {
		s.renderSignIn(w, r, status, next, msg, "")
		return
	}
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	if !s.startBrowserSession(w, r, userID, mfa) {
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// signInProblem turns a credential error into page text and status.
func signInProblem(err error) (string, int) {
	switch {
	case errors.Is(err, identity.ErrInvalidCredentials):
		return "Wrong sign-in name, password or code.", http.StatusUnauthorized
	case errors.Is(err, identity.ErrMFARequired):
		return "Enter your password again, with your authenticator code.", http.StatusUnauthorized
	case errors.Is(err, identity.ErrRateLimited):
		return "Too many attempts. Try again later.", http.StatusTooManyRequests
	}
	return "", 0
}

func (s *Server) startBrowserSession(w http.ResponseWriter, r *http.Request, userID string, mfa bool) bool {
	cookie, err := s.Identity.CreateBrowserSession(r.Context(), userID, mfa)
	if err != nil {
		writeInternal(w, r, err)
		return false
	}
	s.setSessionCookie(w, cookie, int((7 * 24 * time.Hour).Seconds()))
	return true
}

func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	p, ok, err := s.browserPrincipal(r)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	if ok {
		if err := s.Identity.EndSession(r.Context(), p.UserID, p.SessionID); err != nil {
			writeInternal(w, r, err)
			return
		}
	}
	s.setSessionCookie(w, "", -1)
	http.Redirect(w, r, "/v1/signin?reason=signedout", http.StatusSeeOther)
}

func (s *Server) handleRegisterPage(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	q := r.URL.Query()
	invite := q.Get("invite")
	render(w, r, http.StatusOK, "register", pageData{
		Title: "Create account", Next: safeNext(q.Get("next")), Invite: invite, Open: invite != "" || s.DevMode,
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	ctx := r.Context()
	invite, next := r.PostFormValue("invite"), safeNext(r.PostFormValue("next"))
	data := pageData{Title: "Create account", Next: next, Invite: invite, Open: true}
	fail := func(status int, msg string) {
		data.Error = msg
		render(w, r, status, "register", data)
	}
	if invite == "" && !s.DevMode {
		data.Open = false
		render(w, r, http.StatusForbidden, "register", data)
		return
	}
	if err := s.Identity.AllowRegistration(ctx, s.clientIP(r)); errors.Is(err, identity.ErrRateLimited) {
		fail(http.StatusTooManyRequests, "Too many attempts. Try again later.")
		return
	} else if err != nil {
		writeInternal(w, r, err)
		return
	}

	userID, codes, err := s.registerAccount(ctx, r.PostFormValue("name"), r.PostFormValue("display_name"), r.PostFormValue("password"), invite)
	switch {
	case err == nil:
	case errors.Is(err, identity.ErrInvalidName):
		fail(http.StatusBadRequest, "That is not a valid username, phone number or email.")
		return
	case errors.Is(err, identity.ErrInvalidDisplayName):
		fail(http.StatusBadRequest, "Use a name of 100 characters or fewer.")
		return
	case errors.Is(err, identity.ErrWeakPassword):
		fail(http.StatusBadRequest, "Use a longer, less common password of at least 10 characters.")
		return
	case errors.Is(err, identity.ErrNameTaken):
		fail(http.StatusConflict, "That sign-in name is taken.")
		return
	case errors.Is(err, directory.ErrInvitationInvalid):
		fail(http.StatusBadRequest, "This invitation is invalid, used or expired.")
		return
	default:
		writeInternal(w, r, err)
		return
	}
	if !s.startBrowserSession(w, r, userID, false) {
		return
	}
	render(w, r, http.StatusOK, "codes", pageData{Title: "Recovery codes", Codes: codes, Next: next})
}

// registerAccount creates a user with recovery codes and their first tenant, for
// both the web page and the mobile API. An invitation joins that tenant; any
// other new user gets a tenant of their own and runs it, so every active user
// has a membership.
func (s *Server) registerAccount(ctx context.Context, name, displayName, password, invite string) (string, []string, error) {
	var userID string
	var codes []string
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var err error
		userID, err = s.Identity.CreateUser(ctx, tx, "self", identity.NewUser{Name: name, Password: password, DisplayName: displayName})
		if err != nil {
			return err
		}
		if codes, err = s.Identity.IssueRecoveryCodes(ctx, tx, userID); err != nil {
			return err
		}
		actor := audit.ActorUser(userID)
		if invite != "" {
			_, err = s.Directory.AcceptInvitation(ctx, tx, actor, invite, userID)
			return err
		}
		tenant, err := s.Directory.CreateTenant(ctx, tx, actor, "", name)
		if err != nil {
			return err
		}
		_, err = s.Directory.AddMember(ctx, tx, actor, tenant.ID, userID, directory.RoleAdmin)
		return err
	})
	if err != nil {
		return "", nil, err
	}
	return userID, codes, nil
}

func (s *Server) handleRecoverPage(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	render(w, r, http.StatusOK, "recover", pageData{Title: "Recover account"})
}

func (s *Server) handleRecover(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	err := s.Identity.Recover(r.Context(), identity.Recovery{
		Name: r.PostFormValue("name"), Code: r.PostFormValue("recovery_code"), SecondCode: r.PostFormValue("second_code"),
		TOTP: r.PostFormValue("code"), NewPassword: r.PostFormValue("new_password"), IP: s.clientIP(r),
	})
	data := pageData{Title: "Recover account"}
	switch {
	case err == nil:
		render(w, r, http.StatusOK, "done", pageData{Title: "Password changed", Notice: "You are signed out everywhere."})
	case errors.Is(err, identity.ErrWeakPassword):
		data.Error = "Use a longer, less common password of at least 10 characters."
		render(w, r, http.StatusBadRequest, "recover", data)
	case errors.Is(err, identity.ErrInvalidCredentials):
		data.Error = "Those details did not match. An account with an authenticator needs its code or a second recovery code."
		render(w, r, http.StatusUnauthorized, "recover", data)
	case errors.Is(err, identity.ErrRateLimited):
		data.Error = "Too many attempts. Try again later."
		render(w, r, http.StatusTooManyRequests, "recover", data)
	default:
		writeInternal(w, r, err)
	}
}

func (s *Server) handleResetPage(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	render(w, r, http.StatusOK, "reset", pageData{Title: "Set a new password", Token: r.URL.Query().Get("token")})
}

func (s *Server) handleReset(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	token := r.PostFormValue("token")
	err := s.Identity.ResetPassword(r.Context(), token, r.PostFormValue("new_password"))
	data := pageData{Title: "Set a new password", Token: token}
	switch {
	case err == nil:
		render(w, r, http.StatusOK, "done", pageData{Title: "Password changed", Notice: "You are signed out everywhere."})
	case errors.Is(err, identity.ErrWeakPassword):
		data.Error = "Use a longer, less common password of at least 10 characters."
		render(w, r, http.StatusBadRequest, "reset", data)
	case errors.Is(err, identity.ErrInvalidCredentials):
		data.Error = "This link is invalid, used or expired."
		render(w, r, http.StatusBadRequest, "reset", data)
	default:
		writeInternal(w, r, err)
	}
}

func (s *Server) handleJoinPage(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	render(w, r, http.StatusOK, "join", pageData{Title: "Join tenant", Invite: r.URL.Query().Get("invite")})
}

func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	ctx := r.Context()
	invite := r.PostFormValue("invite")
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		_, err := s.Directory.AcceptInvitation(ctx, tx, audit.ActorUser(p.UserID), invite, p.UserID)
		return err
	})
	data := pageData{Title: "Join tenant", Invite: invite}
	switch {
	case err == nil:
		http.Redirect(w, r, defaultNext, http.StatusSeeOther)
	case errors.Is(err, directory.ErrExists):
		data.Error = "You are already a member of this tenant."
		render(w, r, http.StatusConflict, "join", data)
	case errors.Is(err, directory.ErrInvitationInvalid):
		data.Error = "This invitation is invalid, used or expired."
		render(w, r, http.StatusBadRequest, "join", data)
	default:
		writeInternal(w, r, err)
	}
}

func (s *Server) renderAccount(w http.ResponseWriter, r *http.Request, p identity.Principal, status int, data pageData) {
	account, err := s.Identity.GetAccount(r.Context(), p.UserID)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	console, org, err := s.adminHomes(r, p)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	data.Title, data.Account, data.ConsoleURL, data.OrgURL, data.Wide, data.Here = "Your account", account, console, org, true, defaultNext
	render(w, r, status, "account", data)
}

// renderTOTP allows images from data URIs, which this page alone of the account
// pages needs, for the QR code.
func (s *Server) renderTOTP(w http.ResponseWriter, r *http.Request, enrollment identity.TOTPEnrollment) {
	png, err := qrcode.Encode(enrollment.URL, qrcode.Medium, 440)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; frame-ancestors 'none'")
	render(w, r, http.StatusOK, "totp", pageData{
		Title: "Set up authenticator", Enrollment: enrollment, TOTPLink: template.URL(enrollment.URL),
		TOTPImage: template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)),
	})
}

func (s *Server) handleAccountPage(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	s.renderAccount(w, r, p, http.StatusOK, pageData{})
}

// handleAccount applies one change. Every credential change needs the current
// password and any enrolled factor, which the identity methods check.
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	ctx := r.Context()
	reauth := identity.Reauth{Password: r.PostFormValue("password"), Code: r.PostFormValue("code")}
	var err error
	notice := ""
	switch r.PostFormValue("action") {
	case "display_name":
		err = s.Identity.SetDisplayName(ctx, p.UserID, r.PostFormValue("display_name"))
		notice = "Name saved."
	case "password":
		err = s.Identity.ChangePassword(ctx, p.UserID, p.SessionID, r.PostFormValue("new_password"), reauth)
		notice = "Password changed. Your other sessions have ended."
	case "name_add":
		err = s.Identity.AddName(ctx, p.UserID, r.PostFormValue("name"), reauth)
		notice = "Name added."
	case "name_remove":
		var kind, value string
		if kind, value, err = s.Identity.Normalize(r.PostFormValue("name")); err == nil {
			err = s.Identity.RemoveName(ctx, p.UserID, kind, value, reauth)
		}
		notice = "Name removed."
	case "totp_start":
		var account identity.Account
		var enrollment identity.TOTPEnrollment
		if account, err = s.Identity.GetAccount(ctx, p.UserID); err == nil {
			enrollment, err = s.Identity.StartTOTP(ctx, p.UserID, account.Label(), reauth)
		}
		if err == nil {
			s.renderTOTP(w, r, enrollment)
			return
		}
	case "totp_confirm":
		err = s.Identity.ConfirmTOTP(ctx, p.UserID, p.SessionID, reauth.Code)
		notice = "Authenticator on. Your other sessions have ended."
	case "totp_disable":
		err = s.Identity.DisableTOTP(ctx, p.UserID, reauth)
		notice = "Authenticator off."
	case "codes":
		var codes []string
		if codes, err = s.Identity.RegenerateRecoveryCodes(ctx, p.UserID, reauth); err == nil {
			render(w, r, http.StatusOK, "codes", pageData{Title: "Recovery codes", Codes: codes, Next: defaultNext})
			return
		}
	case "device_revoke":
		// Doing this with a password is the lost-phone path.
		err = s.Identity.RevokeDevice(ctx, p.UserID, r.PostFormValue("device_id"), reauth)
		notice = "Device removed."
	case "signout_all":
		if err = s.Identity.SignOutEverywhere(ctx, p.UserID); err == nil {
			s.setSessionCookie(w, "", -1)
			http.Redirect(w, r, "/v1/signin", http.StatusSeeOther)
			return
		}
	default:
		s.renderAccount(w, r, p, http.StatusBadRequest, pageData{Error: "Unknown action."})
		return
	}

	switch {
	case err == nil:
		s.renderAccount(w, r, p, http.StatusOK, pageData{Notice: notice})
	case errors.Is(err, identity.ErrInvalidCredentials), errors.Is(err, identity.ErrMFARequired):
		s.renderAccount(w, r, p, http.StatusUnauthorized, pageData{Error: "Wrong password or code."})
	case errors.Is(err, identity.ErrWeakPassword):
		s.renderAccount(w, r, p, http.StatusBadRequest, pageData{Error: "Use a longer, less common password of at least 10 characters."})
	case errors.Is(err, identity.ErrInvalidName):
		s.renderAccount(w, r, p, http.StatusBadRequest, pageData{Error: "That is not a valid username, phone number or email."})
	case errors.Is(err, identity.ErrInvalidDisplayName):
		s.renderAccount(w, r, p, http.StatusBadRequest, pageData{Error: "Use a name of 100 characters or fewer."})
	case errors.Is(err, identity.ErrNameTaken):
		s.renderAccount(w, r, p, http.StatusConflict, pageData{Error: "That sign-in name is taken."})
	case errors.Is(err, identity.ErrLastName):
		s.renderAccount(w, r, p, http.StatusBadRequest, pageData{Error: "Keep at least one sign-in name."})
	case errors.Is(err, identity.ErrDeviceRevoked):
		s.renderAccount(w, r, p, http.StatusBadRequest, pageData{Error: "That device is already removed."})
	case errors.Is(err, identity.ErrMFAMandatory):
		s.renderAccount(w, r, p, http.StatusForbidden, pageData{Error: "Your role or tenant requires an authenticator."})
	default:
		writeInternal(w, r, err)
	}
}
