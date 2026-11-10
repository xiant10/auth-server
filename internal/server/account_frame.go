package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/xiant10/t10-modkit/frame"

	"t10-auth-server/internal/identity"
)

// The account page wears the frame every t10 app draws: the same Apps list and
// account menu, and the person's theme. It offers a way back to the app it was
// opened from, which the app names in return_to.

// accountBackCookie keeps the app to go back to while the person works on the
// account page, whose forms post back to it.
const accountBackCookie = "t10_account_back"

// backPlace is the app an address belongs to, if it's one of this deployment's:
// Workbench, the console or a business app with its own address. Anything else
// gets no link.
func (s *Server) backPlace(raw, lang string) (label string, ok bool) {
	target, err := url.Parse(raw)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
		return "", false
	}
	same := func(base string) bool {
		u, err := url.Parse(base)
		return err == nil && base != "" && u.Scheme == target.Scheme && u.Host == target.Host
	}
	switch {
	case same(s.WorkbenchURL):
		return translate(lang, "Workbench"), true
	case same(s.ConsoleURL):
		return translate(lang, "Platform console"), true
	}
	for id, base := range s.AppURLs {
		if !same(base) {
			continue
		}
		if s.Roles != nil {
			if m, ok := s.Roles.Catalog().Module(id); ok && m.App != nil {
				if lang == langZH && m.App.LabelZH != "" {
					return m.App.LabelZH, true
				}
				return m.App.Label, true
			}
		}
		return id, true
	}
	return "", false
}

// rememberBack keeps a valid return_to for the account page's later posts.
func (s *Server) rememberBack(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("return_to")
	if raw == "" {
		return
	}
	if _, ok := s.backPlace(raw, langEN); !ok {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: accountBackCookie, Value: url.QueryEscape(raw), Path: accountPath, HttpOnly: true, Secure: s.secureCookies(), SameSite: http.SameSiteLaxMode})
}

// back is the app the account page goes back to, from the request or the cookie.
func (s *Server) back(r *http.Request, lang string) (href, label string) {
	raw := r.URL.Query().Get("return_to")
	if raw == "" {
		if c, err := r.Cookie(accountBackCookie); err == nil {
			raw, _ = url.QueryUnescape(c.Value)
		}
	}
	if label, ok := s.backPlace(raw, lang); ok {
		return raw, label
	}
	return "", ""
}

// framed fills what the frame shows: the Apps list from homes, the account menu
// and the person's theme. On the account page itself the menu needs no Account item.
func (s *Server) framed(r *http.Request, p identity.Principal, found homes, name string, data *pageData) {
	lang := requestLang(r)
	var h frame.Homes
	if raw, err := json.Marshal(found); err == nil {
		_ = json.Unmarshal(raw, &h)
	}
	prefs, err := s.Identity.GetPreferences(r.Context(), p.UserID)
	if err != nil {
		slog.Warn("preferences not read", "error", err)
	}
	data.Theme = prefs.Theme
	data.Places = frame.Places(h, "", frame.Account, lang == langZH)
	data.Menu = frame.Menu{
		Name: name, Lang: lang, Theme: prefs.Theme, Here: accountPath,
		LanguageAction: "/v1/language", ThemeAction: "/v1/theme", SignOutAction: "/v1/signout",
	}
	data.BackURL, data.BackLabel = s.back(r, lang)
}

// handleTheme saves the person's theme, so every t10 app shows it, and goes back.
func (s *Server) handleTheme(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	if theme := r.PostFormValue("theme"); frame.ValidTheme(theme) {
		if _, err := s.Identity.SetPreferences(r.Context(), p.UserID, identity.Preferences{Theme: theme}); err != nil {
			slog.Warn("theme not saved", "error", err)
		}
	}
	next := safeNext(r.PostFormValue("next"))
	if !strings.HasPrefix(next, "/v1/") {
		next = accountPath
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}
