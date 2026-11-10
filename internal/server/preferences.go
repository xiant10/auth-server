package server

import (
	"errors"
	"net/http"

	"t10-auth-server/internal/identity"
)

// A person's language and theme live here, so every app shows the ones they chose
// in any of them. Apps read them after sign-in and save each change.

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
	if errors.Is(err, identity.ErrInvalidPreference) {
		writeError(w, http.StatusBadRequest, "invalid_request", "language is en or zh-Hans, and theme is system, light or dark")
		return
	}
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, prefs)
}
