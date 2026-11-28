package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"auth-server/internal/agents"
	"auth-server/internal/identity"
)

// A person's language and theme live here, so every app shows the ones they chose.
// They choose them on the account page; apps only read them. The answer also says
// which languages the deployment offers.

func (s *Server) handleMyPreferences(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	prefs, err := s.Identity.GetPreferences(r.Context(), p.UserID)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, prefs)
}

func (s *Server) handleSetMyPreferences(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var change identity.Preferences
	if !decodeJSON(w, r, &change) {
		return
	}
	prefs, err := s.Identity.SetPreferences(r.Context(), p.UserID, change)
	if errors.Is(err, identity.ErrLanguageNotOffered) {
		writeError(w, http.StatusBadRequest, "invalid_request", "this deployment offers only "+strings.Join(s.Identity.Languages(), ", "))
		return
	}
	if errors.Is(err, identity.ErrInvalidPreference) {
		writeError(w, http.StatusBadRequest, "invalid_request", "language is en or zh-Hans, theme is system, light or dark, and greeting is personal, simple or off")
		return
	}
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, prefs)
}

// handleUserPreferences lets a service read a person's preferences, such as an agent
// runtime checking how they like to be greeted on a call. Nothing here is secret, and
// a service can't change them.
func (s *Server) handleUserPreferences(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	prefs, err := s.Identity.GetPreferences(r.Context(), r.PathValue("id"))
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "not_found", "no such user")
		return
	}
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, prefs)
}

// handleMyAutoApply answers the modules, by action prefix, the person lets
// their assistant act in without asking, in their current tenant.
func (s *Server) handleMyAutoApply(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	if p.TenantID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "choose a tenant first")
		return
	}
	modules, err := s.Agents.AutoApply(r.Context(), p.UserID, p.TenantID)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"modules": modules})
}

// handleSetMyAutoApply replaces that choice. Only a person's own session can:
// an agent's token has none, so an agent can never widen what it may do.
func (s *Server) handleSetMyAutoApply(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		Modules *[]string `json:"modules"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Modules == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "modules is required")
		return
	}
	modules, err := s.Agents.SetAutoApply(r.Context(), p.UserID, p.TenantID, *req.Modules)
	switch {
	case errors.Is(err, agents.ErrInvalidPrefix):
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	case errors.Is(err, agents.ErrNoTenant):
		writeError(w, http.StatusBadRequest, "invalid_request", "choose a tenant first")
		return
	case err != nil:
		writeInternal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"modules": modules})
}
