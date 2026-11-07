package server

import (
	"encoding/json"
	"net/http"
	"net/url"

	"t10-auth-server/internal/identity"
)

// Only a registered web client's exact callback origin can receive the result.
// No caller-provided query, fragment, credentials, or arbitrary path is accepted.
func browserLogoutRedirect(client identity.Client, target string) bool {
	u, err := url.Parse(target)
	if err != nil || client.Type != identity.ClientConfidential || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Path != "/signed-out" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return client.AllowsRedirect(u.Scheme + "://" + u.Host + "/auth/callback")
}

func (s *Server) handleBrowserLogoutTicket(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var body struct {
		ClientID string `json:"client_id"`
		ReturnTo string `json:"return_to"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid sign-out request")
		return
	}
	client, ok := s.Identity.Client(body.ClientID)
	if !ok || !browserLogoutRedirect(client, body.ReturnTo) {
		writeError(w, http.StatusBadRequest, "invalid_request", "unregistered sign-out destination")
		return
	}
	ticket, err := s.Issuer.MintBrowserLogout(p.UserID, body.ReturnTo)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"ticket": ticket})
}

// Top-level navigation sends the auth host's SameSite=Lax cookie even when the
// client is on another site. A short-lived, user-bound ticket authorizes this
// request; plain GETs and other users' tickets cannot sign a browser out.
func (s *Server) handleBrowserLogout(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	claims, err := s.Issuer.VerifyBrowserLogout(r.URL.Query().Get("ticket"))
	if err != nil || claims.Subject == "" || claims.LogoutRedirect == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "sign-out link expired or invalid; retry from Workbench")
		return
	}
	p, ok, err := s.browserPrincipal(r)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	if ok {
		if p.UserID != claims.Subject {
			writeError(w, http.StatusForbidden, "forbidden", "sign-out belongs to a different account")
			return
		}
		if err := s.Identity.EndSession(r.Context(), p.UserID, p.SessionID); err != nil {
			writeInternal(w, r, err)
			return
		}
	}
	s.setSessionCookie(w, "", -1)
	http.Redirect(w, r, claims.LogoutRedirect, http.StatusSeeOther)
}
