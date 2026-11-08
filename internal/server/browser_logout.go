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
	ticket, err := s.Issuer.MintBrowserLogout(p.UserID, p.SessionID, body.ReturnTo)
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
		render(w, r, http.StatusBadRequest, "signout_again", pageData{Title: "Sign out of t10?", Error: "That sign-out link ran out. Sign out here instead."})
		return
	}
	p, ok, err := s.browserPrincipal(r)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	if ok && p.UserID != claims.Subject {
		render(w, r, http.StatusForbidden, "signout_again", pageData{Title: "Sign out of t10?", Error: "This browser is signed in to t10 with a different account. Sign out of that one too?"})
		return
	}
	if err := s.Identity.EndBrowser(r.Context(), claims.Subject, claims.SessionID); err != nil {
		writeInternal(w, r, err)
		return
	}
	if ok {
		if err := s.Identity.EndBrowser(r.Context(), p.UserID, p.SessionID); err != nil {
			writeInternal(w, r, err)
			return
		}
	}
	s.setSessionCookie(w, "", -1)
	http.Redirect(w, r, claims.LogoutRedirect, http.StatusSeeOther)
}

// handleSignOutPage is for an app whose own session has already gone, so it can't
// get a ticket. The post is same-origin, so nothing but this page can send it.
func (s *Server) handleSignOutPage(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	_, ok, err := s.browserPrincipal(r)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	if !ok {
		http.Redirect(w, r, "/v1/signin?reason=signedout", http.StatusSeeOther)
		return
	}
	render(w, r, http.StatusOK, "signout_again", pageData{Title: "Sign out of t10?", Notice: "This signs you out of every t10 app on this browser."})
}

// handleSessionAlive answers an app checking that the sign-in behind its session
// hasn't ended. accessUser has already checked that against the database.
func (s *Server) handleSessionAlive(w http.ResponseWriter, _ *http.Request, _ identity.Principal) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
