package server

import (
	"cmp"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/identity"
)

// orgTenant is the tenant an org read names. A service token has none of its
// own, so each read says which one it means.
func orgTenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	tenantID := r.URL.Query().Get("tenant")
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "tenant is required")
		return "", false
	}
	return tenantID, true
}

func writeOrg(w http.ResponseWriter, r *http.Request, body any, err error) {
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, body)
	case errors.Is(err, directory.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such member or unit in that tenant")
	default:
		writeInternal(w, r, err)
	}
}

func (s *Server) handleOrgUnits(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	tenantID, ok := orgTenant(w, r)
	if !ok {
		return
	}
	units, err := s.Directory.ListUnits(r.Context(), tenantID)
	writeOrg(w, r, map[string]any{"units": units}, err)
}

func (s *Server) handleOrgMember(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	tenantID, ok := orgTenant(w, r)
	if !ok {
		return
	}
	member, err := s.Directory.OrgMember(r.Context(), tenantID, r.PathValue("id"))
	writeOrg(w, r, member, err)
}

func (s *Server) handleOrgMembers(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	tenantID, ok := orgTenant(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit, err := strconv.Atoi(cmp.Or(q.Get("limit"), "100"))
	status := q.Get("status")
	if err != nil || limit < 1 || limit > directory.MaxMemberPage || (status != "" && status != directory.MemberActive) {
		writeError(w, http.StatusBadRequest, "invalid_request", "limit or status is invalid")
		return
	}
	members, next, err := s.Directory.OrgMembers(r.Context(), tenantID, directory.MemberQuery{
		Search: q.Get("q"), UnitID: q.Get("unit"), ActiveOnly: status != "", After: q.Get("cursor"), Limit: limit,
	})
	writeOrg(w, r, map[string]any{"members": members, "next_cursor": next}, err)
}

func (s *Server) handleOrgReports(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	tenantID, ok := orgTenant(w, r)
	if !ok {
		return
	}
	reports, err := s.Directory.Reports(r.Context(), tenantID, r.PathValue("id"), r.URL.Query().Get("transitive") == "true")
	writeOrg(w, r, map[string]any{"user_ids": reports}, err)
}

func (s *Server) handleOrgUnitMembers(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	tenantID, ok := orgTenant(w, r)
	if !ok {
		return
	}
	members, err := s.Directory.UnitMembers(r.Context(), tenantID, r.PathValue("id"), r.URL.Query().Get("transitive") == "true")
	writeOrg(w, r, map[string]any{"user_ids": members}, err)
}

// A tenant admin's token names its tenant, so these routes take it from the
// path. PUT replaces the whole value: a field left out is cleared.

func (s *Server) handleTenantUnits(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	units, err := s.Directory.ListUnits(r.Context(), r.PathValue("id"))
	if err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"units": units})
}

type unitRequest struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	ParentID   string `json:"parent_id"`
	LeadUserID string `json:"lead_user_id"`
}

func (s *Server) handleCreateUnit(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req unitRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	unit, err := s.Directory.CreateUnit(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), req.Name, req.Kind, req.ParentID)
	if err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, unit)
}

func (s *Server) handleUpdateUnit(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req unitRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	id := r.PathValue("unit")
	err := s.Directory.UpdateUnit(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), id, req.Name, req.Kind, req.ParentID, req.LeadUserID)
	if err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, directory.Unit{ID: id, ParentID: req.ParentID, Name: strings.TrimSpace(req.Name), Kind: req.Kind, LeadUserID: req.LeadUserID})
}

// handleDeleteUnit takes move=up to move the unit's members and child units to
// its parent first. Without it, a unit in use is refused.
func (s *Server) handleDeleteUnit(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	move := r.URL.Query().Get("move")
	if move != "" && move != "up" {
		writeError(w, http.StatusBadRequest, "invalid_request", "move is invalid")
		return
	}
	err := s.Directory.DeleteUnit(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), r.PathValue("unit"), move == "up")
	if err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetPlacement(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	member, err := s.Directory.OrgMember(r.Context(), r.PathValue("id"), r.PathValue("user"))
	if err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, member)
}

func (s *Server) handleSetPlacement(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		ManagerUserID string `json:"manager_user_id"`
		OrgUnitID     string `json:"org_unit_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	tenantID, userID := r.PathValue("id"), r.PathValue("user")
	if err := s.Directory.SetPlacement(r.Context(), audit.ActorUser(p.UserID), tenantID, userID, req.ManagerUserID, req.OrgUnitID); err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	s.handleGetPlacement(w, r, p)
}

// handleSetPlacements places several members in one change, all or none.
func (s *Server) handleSetPlacements(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		Placements []directory.Placement `json:"placements"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.Directory.SetPlacements(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), req.Placements); err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
