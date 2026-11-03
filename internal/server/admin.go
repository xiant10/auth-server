package server

import (
	"errors"
	"net/http"
	"net/url"
	"slices"

	"t10-auth-server/internal/agents"
	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/identity"
)

const (
	adminTenantLimit = 200
	adminAuditLimit  = 100
	tenantAuditLimit = 30
	tenantGrantLimit = 50
	adminUserLimit   = 200
)

// adminData is what the admin templates render. Scope drives the banner, which
// is how the UI keeps platform-wide and tenant-scoped work apart.
type adminData struct {
	Title, Scope  string
	Error, Notice string
	// Nav marks the sidebar's current item; Tab the tenant page's current tab.
	Nav, Tab string
	// Nonce is set on a page with something to copy, which allows its script.
	Nonce string
	// Here is this page's own address, which the language switch returns to.
	Here string
	// Account fills the account popup.
	Account identity.Account
	User    string
	UserID  string
	// PlatformRole means the viewer holds the role; CanPlatform means they may
	// use it now, with a recent enough second factor.
	PlatformRole, CanPlatform bool
	// AgentControl is the operator console's address, if this platform has one.
	AgentControl string

	Tenant  directory.Tenant
	Tenants []directory.TenantSummary
	Users   []directory.UserSummary
	Mine    []directory.UserTenant
	Members []directory.MemberDetail
	Units   []directory.Unit
	Grants  []agents.GrantRow
	Audit   []audit.Record
	Search  string
	Stats   []stat

	Reset     *resetResult
	InviteURL string
	JoinURL   string
}

type resetResult struct {
	Name, URL string
}

type stat struct {
	Value int
	Label string
}

// The tenant page's tabs.
const (
	tabMembers  = "members"
	tabOrg      = "org"
	tabAgents   = "agents"
	tabInvite   = "invite"
	tabSecurity = "security"
	tabActivity = "activity"
)

const (
	scopePlatform = "platform"
	scopeTenant   = "tenant"
)

type adminDecision int

const (
	adminDeny adminDecision = iota
	adminAllow
	// adminStepUp means signing in again would pass: a platform admin whose
	// second factor has gone stale.
	adminStepUp
)

// guardAdmin is the admin UI's half of guard. It sits on the cookie session, so
// it repeats what a token would have proved: a tenant that requires a second
// factor never mints a token without one, so it must refuse a cookie without
// one too.
func (s *Server) guardAdmin(w http.ResponseWriter, r *http.Request, rt route) {
	setPageHeaders(w)
	if r.Method != http.MethodGet && !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "cross-origin request")
		return
	}
	next := "/admin"
	if r.Method == http.MethodGet {
		next = r.URL.RequestURI()
	}
	p, ok, err := s.browserPrincipal(r)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	if !ok {
		http.Redirect(w, r, "/v1/signin?next="+url.QueryEscape(next), http.StatusSeeOther)
		return
	}
	decision, reason, err := s.adminDecide(r, rt.access, p)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	switch decision {
	case adminAllow:
		rt.handler(w, r, p)
	case adminStepUp:
		http.Redirect(w, r, "/v1/signin?reason=stepup&next="+url.QueryEscape(next), http.StatusSeeOther)
	default:
		s.auditDenied(r, p, rt)
		renderDenied(w, r, http.StatusForbidden, "No access", reason)
	}
}

func (s *Server) adminDecide(r *http.Request, a access, p identity.Principal) (adminDecision, string, error) {
	const notAdmin = "You don't have admin access to this page."
	if a == accessAdmin {
		return adminAllow, "", nil
	}
	platform, err := s.isPlatformAdmin(r, p)
	if err != nil {
		return adminDeny, "", err
	}
	if platform {
		return adminAllow, "", nil
	}
	holdsRole, err := s.Directory.IsPlatformAdmin(r.Context(), p.UserID)
	if err != nil {
		return adminDeny, "", err
	}
	if a == accessAdminTenant {
		tenantID := r.PathValue("id")
		admin, err := s.Directory.IsTenantAdmin(r.Context(), p.UserID, tenantID)
		if err != nil {
			return adminDeny, "", err
		}
		if admin {
			required, err := s.Directory.TenantRequiresMFA(r.Context(), s.Pool, tenantID)
			if err != nil {
				return adminDeny, "", err
			}
			if required && !p.MFA {
				return adminDeny, "This tenant requires a second factor. Turn on an authenticator, then sign in with it.", nil
			}
			return adminAllow, "", nil
		}
	}
	switch {
	case holdsRole && p.MFA:
		return adminStepUp, "", nil
	case holdsRole:
		return adminDeny, "Platform admins need an authenticator. Turn one on from your account, then sign in with it.", nil
	}
	return adminDeny, notAdmin, nil
}

// isAnyAdmin reports whether the admin UI has anything for this user.
func (s *Server) isAnyAdmin(r *http.Request, p identity.Principal) (bool, error) {
	role, err := s.Directory.IsPlatformAdmin(r.Context(), p.UserID)
	if err != nil || role {
		return role, err
	}
	tenants, err := s.Directory.ListUserTenants(r.Context(), p.UserID)
	if err != nil {
		return false, err
	}
	for _, t := range tenants {
		if t.Role == directory.RoleAdmin {
			return true, nil
		}
	}
	return false, nil
}

func (s *Server) adminBase(r *http.Request, p identity.Principal, title, scope string) (adminData, error) {
	account, err := s.Identity.GetAccount(r.Context(), p.UserID)
	if err != nil {
		return adminData{}, err
	}
	role, err := s.Directory.IsPlatformAdmin(r.Context(), p.UserID)
	if err != nil {
		return adminData{}, err
	}
	can, err := s.isPlatformAdmin(r, p)
	if err != nil {
		return adminData{}, err
	}
	tenants, err := s.Directory.ListUserTenants(r.Context(), p.UserID)
	if err != nil {
		return adminData{}, err
	}
	data := adminData{
		Title: translate(requestLang(r), title), Scope: scope, User: account.Label(), UserID: p.UserID,
		Here: r.URL.RequestURI(), Account: account, PlatformRole: role, CanPlatform: can,
		AgentControl: s.AgentControlURL,
	}
	for _, t := range tenants {
		if t.Role == directory.RoleAdmin {
			data.Mine = append(data.Mine, t)
		}
	}
	return data, nil
}

// renderAdmin answers in the viewer's language. The page translates its own text,
// and this translates what the handlers wrote.
func renderAdmin(w http.ResponseWriter, r *http.Request, status int, name string, data adminData) {
	if data.InviteURL != "" || data.Reset != nil {
		data.Nonce = newNonce()
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; frame-ancestors 'none'; script-src 'nonce-"+data.Nonce+"'")
	}
	lang := requestLang(r)
	data.Error, data.Notice = translate(lang, data.Error), translate(lang, data.Notice)
	for i := range data.Stats {
		data.Stats[i].Label = translate(lang, data.Stats[i].Label)
	}
	execute(w, r, pagesFor(lang), status, name, data)
}

func renderDenied(w http.ResponseWriter, r *http.Request, status int, title, reason string) {
	lang := requestLang(r)
	execute(w, r, pagesFor(lang), status, "admin_denied", pageData{Title: translate(lang, title), Error: translate(lang, reason)})
}

// pageURL is the address of a page that may be rendering the answer to a post.
func pageURL(path, search string) string {
	if search == "" {
		return path
	}
	return path + "?q=" + url.QueryEscape(search)
}

// adminProblem turns a directory error into page text, or "" if it is a fault.
func adminProblem(err error) (string, int) {
	switch {
	case errors.Is(err, directory.ErrLastAdmin):
		return "A tenant needs at least one active admin. Promote someone else first.", http.StatusConflict
	case errors.Is(err, directory.ErrExists):
		return "That already exists.", http.StatusConflict
	case errors.Is(err, directory.ErrNotFound):
		return "No such tenant, user or unit.", http.StatusNotFound
	case errors.Is(err, directory.ErrInvalid):
		return "That value isn't valid.", http.StatusBadRequest
	case errors.Is(err, directory.ErrCycle):
		return "That would put someone under themselves. Change the other person or unit first.", http.StatusConflict
	case errors.Is(err, directory.ErrUnitInUse):
		return "Move this unit's members and child units first.", http.StatusConflict
	case errors.Is(err, agents.ErrGrantInvalid):
		return "No such agent grant in this tenant.", http.StatusNotFound
	case errors.Is(err, directory.ErrLastPlatformAdmin):
		return "The platform needs at least one admin. Add another one first.", http.StatusConflict
	case errors.Is(err, directory.ErrUserSuspended):
		return "Reactivate this user first.", http.StatusConflict
	case errors.Is(err, identity.ErrPlatformAdminUser):
		return "Remove this user's platform role first.", http.StatusConflict
	case errors.Is(err, identity.ErrUserNotFound):
		return "No such user.", http.StatusNotFound
	}
	return "", 0
}

func (s *Server) handleAdminHome(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	data, err := s.adminBase(r, p, "Overview", "")
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	data.Nav = "home"
	if data.CanPlatform {
		tenants, err := s.Directory.ListTenants(r.Context(), "", adminTenantLimit)
		if err != nil {
			writeInternal(w, r, err)
			return
		}
		suspended := 0
		for _, t := range tenants {
			if t.Status == directory.TenantSuspended {
				suspended++
			}
		}
		data.Stats = []stat{{len(tenants), "Tenants"}, {suspended, "Suspended"}, {len(data.Mine), "You administer"}}
	}
	switch {
	case !data.PlatformRole && len(data.Mine) == 0:
		renderDenied(w, r, http.StatusForbidden, "No access", "You don't administer any tenant.")
	case !data.PlatformRole && len(data.Mine) == 1:
		http.Redirect(w, r, "/admin/tenants/"+url.PathEscape(data.Mine[0].ID), http.StatusSeeOther)
	default:
		renderAdmin(w, r, http.StatusOK, "admin_home", data)
	}
}

func (s *Server) renderTenants(w http.ResponseWriter, r *http.Request, p identity.Principal, status int, notice, problem string) {
	data, err := s.adminBase(r, p, "Tenants", scopePlatform)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	data.Nav, data.Notice, data.Error, data.Search = "tenants", notice, problem, r.URL.Query().Get("q")
	data.Here = pageURL("/admin/tenants", data.Search)
	if data.Tenants, err = s.Directory.ListTenants(r.Context(), data.Search, adminTenantLimit); err != nil {
		writeInternal(w, r, err)
		return
	}
	renderAdmin(w, r, status, "admin_tenants", data)
}

func (s *Server) handleAdminTenants(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	s.renderTenants(w, r, p, http.StatusOK, "", "")
}

func (s *Server) handleAdminCreateTenant(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	tenant, err := s.Directory.Create(r.Context(), audit.ActorUser(p.UserID), r.PostFormValue("id"), r.PostFormValue("name"))
	if msg, status := adminProblem(err); msg != "" {
		s.renderTenants(w, r, p, status, "", msg)
		return
	}
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/tenants/"+url.PathEscape(tenant.ID), http.StatusSeeOther)
}

func (s *Server) handleAdminReleaseName(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	err := s.Identity.ReleaseName(r.Context(), audit.ActorUser(p.UserID), r.PostFormValue("name"))
	switch {
	case errors.Is(err, identity.ErrInvalidName):
		s.renderNames(w, r, p, http.StatusNotFound, "", "No account holds that sign-in name.")
	case err != nil:
		writeInternal(w, r, err)
	default:
		s.renderNames(w, r, p, http.StatusOK, "Sign-in name released.", "")
	}
}

func (s *Server) renderNames(w http.ResponseWriter, r *http.Request, p identity.Principal, status int, notice, problem string) {
	data, err := s.adminBase(r, p, "Sign-in names", scopePlatform)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	data.Nav, data.Notice, data.Error, data.Here = "names", notice, problem, "/admin/names"
	renderAdmin(w, r, status, "admin_names", data)
}

func (s *Server) handleAdminNames(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	s.renderNames(w, r, p, http.StatusOK, "", "")
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, p identity.Principal, status int, notice, problem string) {
	data, err := s.adminBase(r, p, "Users", scopePlatform)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	data.Nav, data.Notice, data.Error, data.Search = "users", notice, problem, r.URL.Query().Get("q")
	data.Here = pageURL("/admin/users", data.Search)
	if data.Users, err = s.Directory.ListUsers(r.Context(), data.Search, adminUserLimit); err != nil {
		writeInternal(w, r, err)
		return
	}
	renderAdmin(w, r, status, "admin_users", data)
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	s.renderUsers(w, r, p, http.StatusOK, "", "")
}

// usersResult re-renders the users page after an action.
func (s *Server) usersResult(w http.ResponseWriter, r *http.Request, p identity.Principal, err error, notice string) {
	msg, status := adminProblem(err)
	switch {
	case msg != "":
		s.renderUsers(w, r, p, status, "", msg)
	case err != nil:
		writeInternal(w, r, err)
	default:
		s.renderUsers(w, r, p, http.StatusOK, notice, "")
	}
}

func (s *Server) handleAdminSetUserStatus(status string) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, p identity.Principal) {
		err := s.Identity.SetUserStatus(r.Context(), audit.ActorUser(p.UserID), r.PathValue("user"), status)
		notice := "User reactivated. They need to sign in again, and stopped agents stay stopped."
		if status == identity.UserSuspended {
			notice = "User suspended and signed out everywhere. Tokens already issued last up to 5 minutes."
		}
		s.usersResult(w, r, p, err, notice)
	}
}

func (s *Server) handleAdminAddPlatformAdmin(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	err := s.Directory.AddPlatformAdmin(r.Context(), audit.ActorUser(p.UserID), r.PathValue("user"))
	s.usersResult(w, r, p, err, "Platform role added. They need an authenticator before they can use it.")
}

func (s *Server) handleAdminRemovePlatformAdmin(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	target := r.PathValue("user")
	err := s.Directory.RemovePlatformAdmin(r.Context(), audit.ActorUser(p.UserID), target)
	// Someone who removed their own role can't see this page any more.
	if err == nil && target == p.UserID {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	s.usersResult(w, r, p, err, "Platform role removed.")
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	data, err := s.adminBase(r, p, "Audit log", scopePlatform)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	data.Nav = "audit"
	if data.Audit, err = audit.List(r.Context(), s.Pool, audit.ScopePlatform, adminAuditLimit); err != nil {
		writeInternal(w, r, err)
		return
	}
	renderAdmin(w, r, http.StatusOK, "admin_audit", data)
}

// tenantView carries what one action adds to the tenant page, which every
// action re-renders on its own tab, so its result shows beside what it changed.
type tenantView struct {
	tab             string
	status          int
	notice, problem string
	reset           *resetResult
	inviteURL       string
	joinURL         string
}

func (s *Server) renderTenant(w http.ResponseWriter, r *http.Request, p identity.Principal, v tenantView) {
	ctx := r.Context()
	tenantID := r.PathValue("id")
	tenant, err := s.Directory.GetTenant(ctx, tenantID)
	if errors.Is(err, directory.ErrNotFound) {
		renderDenied(w, r, http.StatusNotFound, "Not found", "No such tenant.")
		return
	}
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	data, err := s.adminBase(r, p, "", scopeTenant)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	// A tenant's name is its own, so it skips the title's translation.
	data.Title, data.Tenant, data.Notice, data.Error, data.Nav = tenant.Name, tenant, v.notice, v.problem, tenantID
	// A platform admin may be outside this tenant, so Tenants is where they are.
	if !slices.ContainsFunc(data.Mine, func(t directory.UserTenant) bool { return t.ID == tenantID }) {
		data.Nav = "tenants"
	}
	data.Tab = v.tab
	if data.Tab == "" {
		data.Tab = r.URL.Query().Get("tab")
	}
	if !slices.Contains([]string{tabOrg, tabAgents, tabInvite, tabSecurity, tabActivity}, data.Tab) {
		data.Tab = tabMembers
	}
	data.Here = "/admin/tenants/" + url.PathEscape(tenantID) + "?tab=" + data.Tab
	data.Reset, data.InviteURL, data.JoinURL = v.reset, v.inviteURL, v.joinURL
	if data.Members, err = s.Directory.ListMemberDetails(ctx, tenantID); err != nil {
		writeInternal(w, r, err)
		return
	}
	active, admins := 0, 0
	for _, m := range data.Members {
		if m.Status == directory.MemberActive {
			active++
			if m.Role == directory.RoleAdmin {
				admins++
			}
		}
	}
	data.Stats = []stat{{active, "Active members"}, {admins, "Active admins"}, {len(data.Members) - active, "Inactive"}}
	if data.Units, err = s.Directory.ListUnits(ctx, tenantID); err != nil {
		writeInternal(w, r, err)
		return
	}
	if data.Grants, err = s.Agents.ListTenantGrants(ctx, tenantID, tenantGrantLimit); err != nil {
		writeInternal(w, r, err)
		return
	}
	if data.Audit, err = audit.List(ctx, s.Pool, audit.ScopeTenant(tenantID), tenantAuditLimit); err != nil {
		writeInternal(w, r, err)
		return
	}
	if v.status == 0 {
		v.status = http.StatusOK
	}
	renderAdmin(w, r, v.status, "admin_tenant", data)
}

func (s *Server) handleAdminTenant(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	s.renderTenant(w, r, p, tenantView{})
}

// tenantResult re-renders the tenant page after an action.
func (s *Server) tenantResult(w http.ResponseWriter, r *http.Request, p identity.Principal, tab string, err error, notice string) {
	msg, status := adminProblem(err)
	switch {
	case msg != "":
		s.renderTenant(w, r, p, tenantView{tab: tab, status: status, problem: msg})
	case err != nil:
		writeInternal(w, r, err)
	default:
		s.renderTenant(w, r, p, tenantView{tab: tab, notice: notice})
	}
}

func (s *Server) handleAdminSettings(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	required := r.PostFormValue("require_mfa") == "on"
	if required && !p.MFA {
		s.renderTenant(w, r, p, tenantView{
			tab:     tabSecurity,
			status:  http.StatusBadRequest,
			problem: "Turn on an authenticator and sign in with it first, or this setting would lock you out of this page.",
		})
		return
	}
	notice := "Second factor is now optional."
	if required {
		notice = "Second factor is now required. Members without one can't get a token for this tenant."
	}
	err := s.Directory.SetRequireMFA(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), required)
	s.tenantResult(w, r, p, tabSecurity, err, notice)
}

func (s *Server) handleAdminInvite(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	token, err := s.Directory.CreateInvitation(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), r.PostFormValue("role"))
	if err != nil {
		s.tenantResult(w, r, p, tabInvite, err, "")
		return
	}
	s.renderTenant(w, r, p, tenantView{
		tab:       tabInvite,
		inviteURL: s.PublicURL + "/v1/register?invite=" + token,
		joinURL:   s.PublicURL + "/v1/join?invite=" + token,
	})
}

func (s *Server) handleAdminUpdateMember(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	role, status := r.PostFormValue("role"), r.PostFormValue("status")
	_, err := s.Directory.UpdateMember(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), r.PathValue("user"),
		directory.MemberUpdate{Role: &role, Status: &status})
	s.tenantResult(w, r, p, tabMembers, err, "Member updated.")
}

func (s *Server) handleAdminResetLink(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	link, allowed, err := s.issueResetLink(r, p)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	if !allowed {
		s.renderTenant(w, r, p, tenantView{
			tab:     tabMembers,
			status:  http.StatusForbidden,
			problem: "Only a platform admin can reset this account, because it's an admin or also belongs to another tenant.",
		})
		return
	}
	s.renderTenant(w, r, p, tenantView{tab: tabMembers, reset: &resetResult{Name: r.PostFormValue("name"), URL: link}})
}

func (s *Server) handleAdminSetStatus(status string) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, p identity.Principal) {
		err := s.Directory.SetTenantStatus(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), status)
		notice := "Tenant active."
		if status == directory.TenantSuspended {
			notice = "Tenant suspended."
		}
		s.tenantResult(w, r, p, tabSecurity, err, notice)
	}
}

func (s *Server) handleAdminAddMember(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	_, err := s.Directory.Add(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), r.PostFormValue("user_id"), r.PostFormValue("role"))
	s.tenantResult(w, r, p, tabMembers, err, "Member added.")
}
