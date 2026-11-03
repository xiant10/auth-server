package server

import (
	"errors"
	"net/http"

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

// This service has no admin screens. Tenant admins work in workbench, and
// platform admins in the platform console, t10-console, and both call
// the JSON routes here with the person's own token, so every check stays in
// this service. /admin only points the way, for old links and the account page.

// adminHomes says where a signed-in person administers anything. An empty
// value means they have no such role, or this deployment has no such client.
func (s *Server) adminHomes(r *http.Request, p identity.Principal) (console, workbench string, err error) {
	platform, err := s.Directory.IsPlatformAdmin(r.Context(), p.UserID)
	if err != nil {
		return "", "", err
	}
	if platform {
		console = s.ConsoleURL
	}
	tenants, err := s.Directory.ListUserTenants(r.Context(), p.UserID)
	if err != nil {
		return "", "", err
	}
	for _, t := range tenants {
		if t.Role == directory.RoleAdmin && s.WorkbenchURL != "" {
			workbench = s.WorkbenchURL + "/admin"
			break
		}
	}
	return console, workbench, nil
}

// handleAdmin sends someone with one place to go straight there, and shows
// both when they hold both roles.
func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	console, workbench, err := s.adminHomes(r, p)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	switch {
	case console != "" && workbench != "":
		render(w, r, http.StatusOK, "admin_moved", pageData{Title: "Administration", ConsoleURL: console, OrgURL: workbench})
	case console != "":
		http.Redirect(w, r, console, http.StatusSeeOther)
	case workbench != "":
		http.Redirect(w, r, workbench, http.StatusSeeOther)
	default:
		render(w, r, http.StatusForbidden, "problem", pageData{Title: "No access", Error: "You don't administer anything here."})
	}
}

// grantView is a grant as an admin screen shows it.
type grantView struct {
	agents.Grant
	// Who is the user's first sign-in name.
	Who     string `json:"who"`
	Running bool   `json:"running"`
}

func (s *Server) handleTenantGrants(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	rows, err := s.Agents.ListTenantGrants(r.Context(), r.PathValue("id"), tenantGrantLimit)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	grants := make([]grantView, 0, len(rows))
	for _, g := range rows {
		grants = append(grants, grantView{Grant: g.Grant, Who: g.Who, Running: g.Running()})
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": grants})
}

// handleTenantRevokeGrant stops a grant and everything under it. The tenant
// comes from the path the caller holds rights over, so another tenant's grant
// isn't found.
func (s *Server) handleTenantRevokeGrant(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	err := s.Agents.RevokeInTenant(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), r.PathValue("grant"))
	switch {
	case errors.Is(err, agents.ErrGrantInvalid):
		writeError(w, http.StatusNotFound, "not_found", "no such agent grant in this tenant")
	case err != nil:
		writeInternal(w, r, err)
	default:
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	}
}

func (s *Server) handleTenantAudit(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	s.writeAudit(w, r, audit.ScopeTenant(r.PathValue("id")), tenantAuditLimit)
}

func (s *Server) handlePlatformAudit(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	s.writeAudit(w, r, audit.ScopePlatform, adminAuditLimit)
}

func (s *Server) writeAudit(w http.ResponseWriter, r *http.Request, scope string, limit int) {
	records, err := audit.List(r.Context(), s.Pool, scope, limit)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": records})
}
