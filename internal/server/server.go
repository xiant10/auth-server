// Package server is the HTTP surface. Every route declares its required access
// in one table, and a test fails if a route has none.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"t10-auth-server/internal/telemetry"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"t10-auth-server/internal/agents"
	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/identity"
	"t10-auth-server/internal/roles"
)

const (
	// maxBodyBytes caps request bodies; no endpoint takes anything large.
	maxBodyBytes = 64 << 10
	// requestTimeout is shorter than the server's write timeout, so work queued
	// behind a slow database or a busy hasher is dropped rather than piling up.
	requestTimeout = 20 * time.Second
)

// access is the permission a route requires.
type access int

const (
	accessUnset access = iota
	accessPublic
	// accessPage is a public HTML page; writes need a same-origin request.
	accessPage
	// accessBrowser needs a signed-in browser, and redirects to sign-in if not.
	accessBrowser
	// accessService needs a service token from client_credentials.
	accessService
	// accessUser needs a valid user token.
	accessUser
	// accessDevice needs a user token from a mobile app's device session.
	accessDevice
	// accessTenantAdmin needs an admin of the {id} tenant whose token is
	// active in it, or a platform admin.
	accessTenantAdmin
	// accessPlatformAdmin needs a platform admin whose session proved a second
	// factor within identity.PlatformMFAWindow. Dev mode waives the factor,
	// because seeded users have none.
	accessPlatformAdmin
)

type handlerFunc func(w http.ResponseWriter, r *http.Request, p identity.Principal)

type route struct {
	method, pattern string
	access          access
	handler         handlerFunc
}

// Deps are the modules behind the routes.
type Deps struct {
	Pool      *pgxpool.Pool
	Identity  *identity.Service
	Directory *directory.Service
	Agents    *agents.Service
	Roles     *roles.Service
	Issuer    *identity.Issuer
	// DevMode enables the password grant and open registration. Public
	// registration waits on the security review and a CAPTCHA, so outside dev
	// mode only an invitation can create an account.
	DevMode bool
	// PublicURL is the origin pages must post from.
	PublicURL string
	// ConsoleURL is the platform console, and WorkbenchURL the tenant admins'
	// client. /admin sends people to them, and an empty one is left out.
	ConsoleURL, WorkbenchURL string
	// TrustProxy reads the client IP from X-Forwarded-For.
	TrustProxy bool
}

// Server serves the API.
type Server struct {
	Deps
}

// New builds a Server.
func New(deps Deps) *Server {
	return &Server{Deps: deps}
}

func (s *Server) routes() []route {
	return []route{
		{"GET", "/healthz", accessPublic, s.handleHealth},
		{"GET", "/readyz", accessPublic, s.handleReady},
		{"GET", "/.well-known/jwks.json", accessPublic, s.handleJWKS},
		{"POST", "/v1/token", accessPublic, s.handleToken},
		{"POST", "/v1/revoke", accessPublic, s.handleRevoke},

		{"POST", "/v1/challenges", accessPublic, s.handleChallenge},
		{"POST", "/v1/login", accessPublic, s.handleLogin},
		{"POST", "/v1/login/mfa", accessPublic, s.handleLoginMFA},
		{"POST", "/v1/login/register", accessPublic, s.handleLoginRegister},
		{"POST", "/v1/login/recover", accessPublic, s.handleLoginRecover},
		{"POST", "/v1/login/pair", accessPublic, s.handlePair},
		{"POST", "/v1/login/pair/poll", accessPublic, s.handlePairPoll},

		{"GET", "/v1/authorize", accessPage, s.handleAuthorize},
		{"GET", "/v1/signin", accessPage, s.handleSignInPage},
		{"POST", "/v1/signin", accessPage, s.handleSignIn},
		{"POST", "/v1/signout", accessPage, s.handleSignOut},
		{"POST", "/v1/signin/qr", accessPage, s.handleQRStart},
		{"POST", "/v1/signin/qr/poll", accessPage, s.handleQRPoll},
		{"GET", "/v1/register", accessPage, s.handleRegisterPage},
		{"POST", "/v1/register", accessPage, s.handleRegister},
		{"GET", "/v1/recover", accessPage, s.handleRecoverPage},
		{"POST", "/v1/recover", accessPage, s.handleRecover},
		{"GET", "/v1/reset", accessPage, s.handleResetPage},
		{"POST", "/v1/reset", accessPage, s.handleReset},
		{"POST", "/v1/language", accessPage, s.handleLanguage},

		{"GET", "/v1/account", accessBrowser, s.handleAccountPage},
		{"POST", "/v1/account", accessBrowser, s.handleAccount},
		{"GET", "/v1/join", accessBrowser, s.handleJoinPage},
		{"POST", "/v1/join", accessBrowser, s.handleJoin},
		{"GET", "/admin", accessBrowser, s.handleAdmin},
		{"GET", "/admin/{rest...}", accessBrowser, s.handleAdmin},

		{"POST", "/v1/grants", accessService, s.handleCreateGrant},
		{"GET", "/v1/grants/{id}/chain", accessService, s.handleGrantChain},
		{"POST", "/v1/grants/{id}/extend", accessService, s.handleExtendGrant},
		{"POST", "/v1/grants/{id}/revoke", accessService, s.handleRevokeGrant},

		{"GET", "/v1/org/units", accessService, s.handleOrgUnits},
		{"GET", "/v1/org/units/{id}/members", accessService, s.handleOrgUnitMembers},
		{"GET", "/v1/org/members", accessService, s.handleOrgMembers},
		{"GET", "/v1/org/members/{id}", accessService, s.handleOrgMember},
		{"GET", "/v1/org/members/{id}/reports", accessService, s.handleOrgReports},
		{"GET", "/v1/entitlements", accessService, s.handleEntitlements},

		{"POST", "/v1/rooms/admission", accessUser, s.handleAdmission},
		{"GET", "/v1/me", accessUser, s.handleMe},
		{"GET", "/v1/me/access", accessUser, s.handleMeAccess},
		{"GET", "/v1/me/permissions", accessUser, s.handleMyPermissions},
		{"PATCH", "/v1/me", accessUser, s.handleUpdateMe},
		{"POST", "/v1/logout", accessUser, s.handleLogout},

		{"POST", "/v1/qr/{id}/claim", accessDevice, s.handleQRClaim},
		{"POST", "/v1/qr/{id}/approve", accessDevice, s.handleQRApprove},
		{"POST", "/v1/qr/{id}/deny", accessDevice, s.handleQRDeny},
		{"POST", "/v1/me/password", accessDevice, s.handleMePassword},
		{"POST", "/v1/me/names", accessDevice, s.handleMeAddName},
		{"POST", "/v1/me/names/remove", accessDevice, s.handleMeRemoveName},
		{"POST", "/v1/me/totp/start", accessDevice, s.handleMeTOTPStart},
		{"POST", "/v1/me/totp/confirm", accessDevice, s.handleMeTOTPConfirm},
		{"POST", "/v1/me/totp/disable", accessDevice, s.handleMeTOTPDisable},
		{"POST", "/v1/me/recovery-codes", accessDevice, s.handleMeRecoveryCodes},
		{"POST", "/v1/me/signout-all", accessDevice, s.handleMeSignOutAll},
		{"POST", "/v1/me/invitations/accept", accessDevice, s.handleMeAcceptInvitation},
		{"POST", "/v1/devices/{id}/revoke", accessDevice, s.handleDeviceRevoke},

		{"GET", "/v1/tenants", accessPlatformAdmin, s.handleListTenants},
		{"POST", "/v1/tenants", accessPlatformAdmin, s.handleCreateTenant},
		{"POST", "/v1/tenants/{id}/suspend", accessPlatformAdmin, s.handleSetTenantStatus(directory.TenantSuspended)},
		{"POST", "/v1/tenants/{id}/activate", accessPlatformAdmin, s.handleSetTenantStatus(directory.TenantActive)},
		{"POST", "/v1/tenants/{id}/members", accessPlatformAdmin, s.handleAddMember},
		{"POST", "/v1/identifiers/release", accessPlatformAdmin, s.handleReleaseName},
		{"GET", "/v1/audit", accessPlatformAdmin, s.handlePlatformAudit},
		{"GET", "/v1/runtimes", accessPlatformAdmin, s.handleListRuntimes},
		{"GET", "/v1/users", accessPlatformAdmin, s.handleListUsers},
		{"POST", "/v1/users/{user}/suspend", accessPlatformAdmin, s.handleSetUserStatus(identity.UserSuspended)},
		{"POST", "/v1/users/{user}/activate", accessPlatformAdmin, s.handleSetUserStatus(identity.UserActive)},
		{"PUT", "/v1/users/{user}/platform-admin", accessPlatformAdmin, s.handleAddPlatformAdmin},
		{"DELETE", "/v1/users/{user}/platform-admin", accessPlatformAdmin, s.handleRemovePlatformAdmin},

		{"GET", "/v1/tenants/{id}", accessTenantAdmin, s.handleGetTenant},
		{"PATCH", "/v1/tenants/{id}", accessTenantAdmin, s.handleUpdateTenant},
		{"GET", "/v1/tenants/{id}/members", accessTenantAdmin, s.handleListMembers},
		{"PATCH", "/v1/tenants/{id}/members/{user}", accessTenantAdmin, s.handleUpdateMember},
		{"POST", "/v1/tenants/{id}/members/{user}/reset-link", accessTenantAdmin, s.handleResetLink},
		{"POST", "/v1/tenants/{id}/invitations", accessTenantAdmin, s.handleCreateInvitation},
		{"GET", "/v1/tenants/{id}/units", accessTenantAdmin, s.handleTenantUnits},
		{"POST", "/v1/tenants/{id}/units", accessTenantAdmin, s.handleCreateUnit},
		{"PUT", "/v1/tenants/{id}/units/{unit}", accessTenantAdmin, s.handleUpdateUnit},
		{"DELETE", "/v1/tenants/{id}/units/{unit}", accessTenantAdmin, s.handleDeleteUnit},
		{"GET", "/v1/tenants/{id}/members/{user}/placement", accessTenantAdmin, s.handleGetPlacement},
		{"PUT", "/v1/tenants/{id}/members/{user}/placement", accessTenantAdmin, s.handleSetPlacement},
		{"GET", "/v1/tenants/{id}/grants", accessTenantAdmin, s.handleTenantGrants},
		{"POST", "/v1/tenants/{id}/grants/{grant}/revoke", accessTenantAdmin, s.handleTenantRevokeGrant},
		{"GET", "/v1/tenants/{id}/audit", accessTenantAdmin, s.handleTenantAudit},
		{"GET", "/v1/tenants/{id}/permission-catalog", accessTenantAdmin, s.handlePermissionCatalog},
		{"GET", "/v1/tenants/{id}/roles", accessTenantAdmin, s.handleListRoles},
		{"POST", "/v1/tenants/{id}/roles", accessTenantAdmin, s.handleCreateRole},
		{"GET", "/v1/tenants/{id}/roles/{role}", accessTenantAdmin, s.handleGetRole},
		{"PATCH", "/v1/tenants/{id}/roles/{role}", accessTenantAdmin, s.handleUpdateRole},
		{"GET", "/v1/tenants/{id}/members/{user}/role-assignments", accessTenantAdmin, s.handleListAssignments},
		{"POST", "/v1/tenants/{id}/members/{user}/role-assignments", accessTenantAdmin, s.handleAssignRole},
		{"DELETE", "/v1/tenants/{id}/members/{user}/role-assignments/{assignment}", accessTenantAdmin, s.handleRevokeAssignment},
	}
}

// Handler returns the routed handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range s.routes() {
		key := rt.method + " " + rt.pattern
		mux.Handle(key, telemetry.Wrap(key, s.guard(rt)))
	}
	return wrap(mux)
}

// wrap puts the deadline outside the log: it copies the request, and the mux
// sets the route the log reads on the copy it is handed.
func wrap(mux http.Handler) http.Handler {
	return withDeadline(logRequests(mux))
}

func withDeadline(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// guard enforces a route's access before its handler runs. Any lookup failure
// refuses the request, so authorization fails closed.
func (s *Server) guard(rt route) http.Handler {
	if rt.access == accessUnset {
		panic("route without access: " + rt.method + " " + rt.pattern)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		if s.secureCookies() {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		switch rt.access {
		case accessPublic:
			rt.handler(w, r, identity.Principal{})
			return
		case accessPage, accessBrowser:
			setPageHeaders(w)
			if r.Method != http.MethodGet && !s.sameOrigin(r) {
				writeError(w, http.StatusForbidden, "forbidden", "cross-origin request")
				return
			}
			if rt.access == accessPage {
				rt.handler(w, r, identity.Principal{})
				return
			}
			p, ok, err := s.browserPrincipal(r)
			if err != nil {
				writeInternal(w, r, err)
				return
			}
			if !ok {
				http.Redirect(w, r, "/v1/signin?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			rt.handler(w, r, p)
			return
		case accessService:
			account, err := s.Identity.AuthenticateService(r.Context(), bearerToken(r))
			if errors.Is(err, identity.ErrInvalidToken) {
				w.Header().Set("WWW-Authenticate", "Bearer")
				writeError(w, http.StatusUnauthorized, "invalid_token", "missing, invalid or expired service token")
				return
			}
			if err != nil {
				writeInternal(w, r, err)
				return
			}
			rt.handler(w, r, identity.Principal{Service: account})
			return
		}

		p, err := s.Identity.Authenticate(r.Context(), bearerToken(r))
		if errors.Is(err, identity.ErrInvalidToken) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "invalid_token", "missing, invalid or expired bearer token")
			return
		}
		if err != nil {
			writeInternal(w, r, err)
			return
		}

		allowed, err := s.allowed(r, rt.access, p)
		if err != nil {
			writeInternal(w, r, err)
			return
		}
		if !allowed {
			s.auditDenied(r, p, rt)
			writeError(w, http.StatusForbidden, "forbidden", "not permitted")
			return
		}
		rt.handler(w, r, p)
	})
}

func (s *Server) allowed(r *http.Request, a access, p identity.Principal) (bool, error) {
	switch a {
	case accessUser:
		return true, nil
	case accessDevice:
		return p.DeviceID != "", nil
	case accessPlatformAdmin:
		return s.isPlatformAdmin(r, p)
	case accessTenantAdmin:
		platform, err := s.isPlatformAdmin(r, p)
		if err != nil || platform {
			return platform, err
		}
		tenantID := r.PathValue("id")
		if p.TenantID != tenantID {
			return false, nil
		}
		return s.Directory.IsTenantAdmin(r.Context(), p.UserID, tenantID)
	default:
		return false, nil
	}
}

func (s *Server) isPlatformAdmin(r *http.Request, p identity.Principal) (bool, error) {
	if !p.MFARecent && !s.DevMode {
		return false, nil
	}
	return s.Directory.IsPlatformAdmin(r.Context(), p.UserID)
}

// auditDenied writes outside any transaction, so it uses a context that
// survives the client going away.
func (s *Server) auditDenied(r *http.Request, p identity.Principal, rt route) {
	scope := audit.ScopePlatform
	if id := r.PathValue("id"); id != "" {
		scope = audit.ScopeTenant(id)
	}
	err := audit.Write(context.WithoutCancel(r.Context()), s.Pool, audit.Entry{
		Actor: audit.ActorUser(p.UserID), Scope: scope, Action: "http." + rt.method + " " + rt.pattern,
		Target: r.URL.Path, Outcome: audit.Denied,
	})
	if err != nil {
		slog.ErrorContext(r.Context(), "audit write failed", "error", err)
	}
}

func bearerToken(r *http.Request) string {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

// clientIP is the peer address, or the entry the ingress appended when the
// service sits behind one. Earlier entries are client-supplied.
func (s *Server) clientIP(r *http.Request) string {
	if s.TrustProxy {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			parts := strings.Split(forwarded, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func writeInternal(w http.ResponseWriter, r *http.Request, err error) {
	slog.ErrorContext(r.Context(), "request failed", "method", r.Method, "route", r.Pattern, "error", err)
	writeError(w, http.StatusInternalServerError, "server_error", "internal error")
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// logRequests records method, route and status. It logs the route pattern, not
// the path, which holds QR and user IDs. Headers and bodies stay out too, since
// they carry tokens and passwords.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		route := r.Pattern
		if route == "" {
			route = "unmatched"
		}
		slog.InfoContext(r.Context(), "request", "method", r.Method, "route", route,
			"status", rec.status, "duration_ms", time.Since(start).Milliseconds())
	})
}
