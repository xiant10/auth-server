package server

import (
	"errors"
	"net/http"
	"strconv"

	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/identity"
	"t10-auth-server/internal/roles"
)

// Business roles. Tenant admins build roles from the permissions the deployed
// modules declare; modules read a member's grants on each request. None of this
// touches membership's member/admin role.

func writeRolesError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, roles.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such tenant, member, role or assignment")
	case errors.Is(err, roles.ErrExists):
		writeError(w, http.StatusConflict, "conflict", "a role with that name, or that assignment, already exists")
	case errors.Is(err, roles.ErrStale):
		writeError(w, http.StatusConflict, "stale_revision", "it changed since you read it; read it again")
	case errors.Is(err, roles.ErrRoleDisabled):
		writeError(w, http.StatusConflict, "role_disabled", "enable the role before assigning it")
	case errors.Is(err, roles.ErrUnknownPermission):
		writeError(w, http.StatusBadRequest, "unknown_permission", err.Error())
	case errors.Is(err, roles.ErrUnknownModule):
		writeError(w, http.StatusNotFound, "unknown_module", "that module isn't deployed here")
	case errors.Is(err, roles.ErrNotModuleService):
		writeError(w, http.StatusForbidden, "forbidden", "a service reads only its own module")
	case errors.Is(err, roles.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
	default:
		writeInternal(w, r, err)
	}
}

func (s *Server) handlePermissionCatalog(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	view, err := s.Roles.CatalogFor(r.Context(), r.PathValue("id"))
	if err != nil {
		writeRolesError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	list, err := s.Roles.ListRoles(r.Context(), r.PathValue("id"))
	if err != nil {
		writeRolesError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": list})
}

func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		Name        string    `json:"name"`
		Description string    `json:"description"`
		Permissions *[]string `json:"permissions"`
		Template    *struct {
			Module string `json:"module"`
			ID     string `json:"id"`
		} `json:"template"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	n := roles.NewRole{Name: req.Name, Description: req.Description}
	// Left out, a template's permissions apply; an explicit empty list doesn't.
	if req.Permissions != nil {
		n.Permissions = *req.Permissions
		if n.Permissions == nil {
			n.Permissions = []string{}
		}
	}
	if req.Template != nil {
		n.TemplateModule, n.TemplateID = req.Template.Module, req.Template.ID
	}
	role, err := s.Roles.CreateRole(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), n)
	if err != nil {
		writeRolesError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, role)
}

func (s *Server) handleGetRole(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	role, err := s.Roles.GetRole(r.Context(), r.PathValue("id"), r.PathValue("role"))
	if err != nil {
		writeRolesError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, role)
}

func (s *Server) handleUpdateRole(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		Revision    *int64    `json:"revision"`
		Name        *string   `json:"name"`
		Description *string   `json:"description"`
		Enabled     *bool     `json:"enabled"`
		Permissions *[]string `json:"permissions"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Revision == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "revision is required")
		return
	}
	u := roles.RoleUpdate{Revision: *req.Revision, Name: req.Name, Description: req.Description, Enabled: req.Enabled}
	if req.Permissions != nil {
		u.Permissions = *req.Permissions
		if u.Permissions == nil {
			u.Permissions = []string{}
		}
	}
	role, err := s.Roles.UpdateRole(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), r.PathValue("role"), u)
	if err != nil {
		writeRolesError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, role)
}

func (s *Server) handleListAssignments(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	list, err := s.Roles.ListAssignments(r.Context(), r.PathValue("id"), r.PathValue("user"))
	if err != nil {
		writeRolesError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"assignments": list})
}

func (s *Server) handleAssignRole(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		RoleID string `json:"role_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.RoleID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "role_id is required")
		return
	}
	a, err := s.Roles.Assign(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), r.PathValue("user"), req.RoleID)
	if err != nil {
		writeRolesError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) handleRevokeAssignment(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	revision, err := strconv.ParseInt(r.URL.Query().Get("revision"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "revision is required")
		return
	}
	err = s.Roles.Revoke(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), r.PathValue("user"),
		r.PathValue("assignment"), revision)
	if err != nil {
		writeRolesError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleMyPermissions is the caller's own grants in one module, for showing
// what they can do. Modules never trust it; they read entitlements themselves.
func (s *Server) handleMyPermissions(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	module := r.URL.Query().Get("module")
	if module == "" || p.TenantID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "module and an active tenant are required")
		return
	}
	mine, err := s.Roles.MyPermissions(r.Context(), p.TenantID, p.UserID, module)
	if err != nil {
		writeRolesError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"module": module, "tenant_id": p.TenantID, "active": mine.Active, "grants": mine.Grants})
}

// handleEntitlements is a module's per-request check: membership, account and
// tenant status and current grants, uncached, for up to a page of users. A
// service reads only the module its catalog entry names it for.
func (s *Server) handleEntitlements(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	q := r.URL.Query()
	tenantID, module := q.Get("tenant"), q.Get("module")
	if tenantID == "" || module == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "tenant, module and at least one user are required")
		return
	}
	e, err := s.Roles.EntitlementsFor(r.Context(), p.Service.Name, tenantID, module, q["user"])
	if err != nil {
		writeRolesError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}
