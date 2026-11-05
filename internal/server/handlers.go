package server

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"time"

	"t10-auth-server/internal/agents"
	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/identity"
)

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request, _ identity.Principal) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	if err := s.Pool.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "database unreachable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request, _ identity.Principal) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(s.Issuer.JWKS())
}

type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Tenant       string `json:"tenant"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	CodeVerifier string `json:"code_verifier"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	SessionID    string `json:"session_id"`
	Challenge    string `json:"challenge"`
	Signature    string `json:"signature"`
	GrantID      string `json:"grant_id"`
	SubjectToken string `json:"subject_token"`
	Audience     string `json:"audience"`
}

// parseTokenRequest takes JSON, which the Mac client's password login sends,
// and the form encoding OAuth specifies.
func parseTokenRequest(r *http.Request) (tokenRequest, error) {
	var req tokenRequest
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch mediaType {
	case "application/json":
		err := json.NewDecoder(r.Body).Decode(&req)
		return req, err
	case "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			return req, err
		}
		return tokenRequest{
			GrantType:    r.PostForm.Get("grant_type"),
			Username:     r.PostForm.Get("username"),
			Password:     r.PostForm.Get("password"),
			Tenant:       r.PostForm.Get("tenant"),
			Code:         r.PostForm.Get("code"),
			RedirectURI:  r.PostForm.Get("redirect_uri"),
			CodeVerifier: r.PostForm.Get("code_verifier"),
			ClientID:     r.PostForm.Get("client_id"),
			ClientSecret: r.PostForm.Get("client_secret"),
			RefreshToken: r.PostForm.Get("refresh_token"),
			SessionID:    r.PostForm.Get("session_id"),
			Challenge:    r.PostForm.Get("challenge"),
			Signature:    r.PostForm.Get("signature"),
			GrantID:      r.PostForm.Get("grant_id"),
			SubjectToken: r.PostForm.Get("subject_token"),
			Audience:     r.PostForm.Get("audience"),
		}, nil
	default:
		return req, errors.New("unsupported content type")
	}
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	req, err := parseTokenRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed token request")
		return
	}
	ctx := r.Context()
	switch {
	case req.GrantType == "authorization_code":
		tokens, err := s.Identity.RedeemCode(ctx, identity.Redemption{
			Code: req.Code, ClientID: req.ClientID, ClientSecret: req.ClientSecret,
			RedirectURI: req.RedirectURI, Verifier: req.CodeVerifier, Tenant: req.Tenant,
		})
		writeTokens(w, r, tokens, err)
	case req.GrantType == "refresh_token":
		tokens, err := s.Identity.Refresh(ctx, identity.Refreshing{
			Refresh: req.RefreshToken, ClientID: req.ClientID, ClientSecret: req.ClientSecret, Tenant: req.Tenant,
		})
		writeTokens(w, r, tokens, err)
	case req.GrantType == "device_refresh":
		tokens, err := s.Identity.RefreshDevice(ctx, identity.DeviceRefresh{
			ClientID: req.ClientID, SessionID: req.SessionID, Challenge: req.Challenge, Signature: req.Signature, Tenant: req.Tenant,
		})
		if err != nil {
			writeMobileError(w, r, err)
			return
		}
		writeDeviceTokens(w, tokens)
	case req.GrantType == "client_credentials":
		tokens, err := s.Identity.ServiceToken(ctx, req.ClientID, req.ClientSecret)
		if errors.Is(err, identity.ErrInvalidClient) {
			writeError(w, http.StatusUnauthorized, "invalid_client", "unknown service or wrong secret")
			return
		}
		writeTokens(w, r, tokens, err)
	case req.GrantType == "agent_grant":
		s.handleGrantExchange(w, r, req)
	case req.GrantType == grantTypeTokenExchange:
		s.handleTokenExchange(w, r, req)
	case req.GrantType == "password" && s.DevMode:
		// Outside dev mode this grant does not exist, whatever is seeded.
		token, err := s.Identity.PasswordLogin(ctx, req.Username, req.Password, req.Tenant, s.clientIP(r))
		writeTokens(w, r, identity.Tokens{Access: token.Token, ExpiresAt: token.ExpiresAt}, err)
	default:
		writeError(w, http.StatusBadRequest, "unsupported_grant_type", "grant type not supported")
	}
}

func writeTokens(w http.ResponseWriter, r *http.Request, tokens identity.Tokens, err error) {
	switch {
	case err == nil:
		body := map[string]any{
			"access_token": tokens.Access,
			"token_type":   "Bearer",
			"expires_in":   int(time.Until(tokens.ExpiresAt).Seconds()),
		}
		if tokens.Refresh != "" {
			body["refresh_token"] = tokens.Refresh
		}
		writeJSON(w, http.StatusOK, body)
	case errors.Is(err, identity.ErrInvalidCredentials):
		writeError(w, http.StatusBadRequest, "invalid_grant", "invalid sign-in name or password")
	case errors.Is(err, identity.ErrInvalidGrant):
		writeError(w, http.StatusBadRequest, "invalid_grant", "code or refresh token is invalid or expired")
	case errors.Is(err, identity.ErrInvalidClient):
		writeError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
	case errors.Is(err, identity.ErrRateLimited):
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many attempts")
	case errors.Is(err, identity.ErrMFARequired):
		writeError(w, http.StatusForbidden, "mfa_required", "this tenant requires a second factor; enroll at /v1/account")
	case errors.Is(err, directory.ErrTenantRequired):
		writeError(w, http.StatusBadRequest, "invalid_request", "name a tenant: this user belongs to several")
	case errors.Is(err, directory.ErrTenantDenied), errors.Is(err, directory.ErrNoTenant):
		writeError(w, http.StatusForbidden, "forbidden", "no active membership in that tenant")
	default:
		writeInternal(w, r, err)
	}
}

// handleRevoke ends a client's session. Like RFC 7009, it succeeds for tokens
// it does not recognize.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	req, err := parseTokenRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request")
		return
	}
	err = s.Identity.RevokeRefresh(r.Context(), req.ClientID, req.ClientSecret, req.RefreshToken)
	if errors.Is(err, identity.ErrInvalidClient) {
		writeError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleAdmission(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		Room   string `json:"room"`
		Tenant string `json:"tenant"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed admission request")
		return
	}
	admission, err := s.Agents.Admit(r.Context(), p.UserID, p.TenantID, req.Tenant, req.Room)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, admission)
	case errors.Is(err, agents.ErrInvalidRoom):
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid room name")
	case errors.Is(err, agents.ErrTenantMismatch), errors.Is(err, agents.ErrNoTenant), errors.Is(err, directory.ErrTenantDenied):
		writeError(w, http.StatusForbidden, "forbidden", "room:"+req.Room+"#join not permitted")
	default:
		writeInternal(w, r, err)
	}
}

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request")
		return
	}
	tenant, err := s.Directory.Create(r.Context(), audit.ActorUser(p.UserID), req.ID, req.Name)
	if err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, tenant)
}

func (s *Server) handleGetTenant(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	tenant, err := s.Directory.GetTenant(r.Context(), r.PathValue("id"))
	if err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, tenant)
}

func (s *Server) handleSetTenantStatus(status string) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, p identity.Principal) {
		err := s.Directory.SetTenantStatus(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), status)
		if err != nil {
			writeDirectoryError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": status})
	}
}

// handleListMembers carries names and placement, because an admin screen shows
// them beside each membership.
func (s *Server) handleListMembers(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	members, err := s.Directory.ListMemberDetails(r.Context(), r.PathValue("id"))
	if err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}

func (s *Server) handleAddMember(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request")
		return
	}
	if req.Role == "" {
		req.Role = directory.RoleMember
	}
	member, err := s.Directory.Add(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), req.UserID, req.Role)
	if err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, member)
}

func (s *Server) handleUpdateMember(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		Role   *string `json:"role"`
		Status *string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request")
		return
	}
	member, err := s.Directory.UpdateMember(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), r.PathValue("user"),
		directory.MemberUpdate{Role: req.Role, Status: req.Status})
	if err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, member)
}

func (s *Server) handleUpdateTenant(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		RequireMFA *bool `json:"require_mfa"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RequireMFA == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "require_mfa is required")
		return
	}
	// Requiring a factor the caller didn't sign in with would refuse their next
	// token, so they'd lock themselves out of this setting.
	if *req.RequireMFA && !p.MFA {
		writeError(w, http.StatusConflict, "mfa_needed", "sign in with an authenticator before requiring one")
		return
	}
	id := r.PathValue("id")
	if err := s.Directory.SetRequireMFA(r.Context(), audit.ActorUser(p.UserID), id, *req.RequireMFA); err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	s.handleGetTenant(w, r, p)
}

func (s *Server) handleCreateInvitation(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request")
		return
	}
	if req.Role == "" {
		req.Role = directory.RoleMember
	}
	token, err := s.Directory.CreateInvitation(r.Context(), audit.ActorUser(p.UserID), r.PathValue("id"), req.Role)
	if err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"invite_url": s.PublicURL + "/v1/register?invite=" + token,
		"join_url":   s.PublicURL + "/v1/join?invite=" + token,
	})
}

// handleResetLink issues a 30-minute reset link. Who may receive one is checked
// here because it depends on the target, not only the caller.
func (s *Server) handleResetLink(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	link, allowed, err := s.issueResetLink(r, p)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	if !allowed {
		writeError(w, http.StatusForbidden, "forbidden", "this account needs a platform admin to reset")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"reset_url": link})
}

// issueResetLink applies the reset rule for the {id} tenant's {user}, for the
// API and the admin UI alike.
func (s *Server) issueResetLink(r *http.Request, p identity.Principal) (string, bool, error) {
	tenantID, userID := r.PathValue("id"), r.PathValue("user")
	platform, err := s.isPlatformAdmin(r, p)
	if err != nil {
		return "", false, err
	}
	var allowed bool
	if platform {
		allowed, err = s.Directory.IsMember(r.Context(), tenantID, userID)
	} else {
		allowed, err = s.Directory.CanTenantAdminReset(r.Context(), tenantID, userID)
	}
	if err != nil || !allowed {
		return "", false, err
	}
	token, err := s.Identity.IssueReset(r.Context(), audit.ActorUser(p.UserID), audit.ScopeTenant(tenantID), userID)
	if err != nil {
		return "", false, err
	}
	return s.PublicURL + "/v1/reset?token=" + token, true, nil
}

// handleMeAccess answers what a caller's own token can do, for a service that
// makes access decisions and holds no roles. platform_verified and
// tenant_verified carry the 15-minute rule and the dev-mode waiver, so neither
// is repeated elsewhere.
func (s *Server) handleMeAccess(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	platform, err := s.Directory.IsPlatformAdmin(r.Context(), p.UserID)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	verified, err := s.isPlatformAdmin(r, p)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	tenantAdmin := false
	if p.TenantID != "" {
		if tenantAdmin, err = s.Directory.IsTenantAdmin(r.Context(), p.UserID, p.TenantID); err != nil {
			writeInternal(w, r, err)
			return
		}
	}
	// tenant_verified is the same rule for a tenant's admins: a factor from the
	// last 15 minutes, waived in dev mode, for changes such as tenant policy.
	tenantVerified := tenantAdmin && (p.MFARecent || s.DevMode)
	// modules and module_admin come from business roles, for navigation only:
	// each module checks its own entitlements.
	modules, moduleAdmin, err := s.Roles.Access(r.Context(), p.TenantID, p.UserID, tenantAdmin)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": p.UserID, "active_tenant": p.TenantID, "tenant_admin": tenantAdmin,
		"platform_admin": platform, "mfa": p.MFA, "platform_verified": verified, "tenant_verified": tenantVerified,
		"modules": modules, "module_admin": moduleAdmin,
	})
}

// handleListTenants is the platform's tenant list, for the console.
func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	tenants, err := s.Directory.ListTenants(r.Context(), r.URL.Query().Get("q"), adminTenantLimit)
	if err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": tenants})
}

// handleListRuntimes is the reviewed runtime list from the clients file. It holds
// no credentials, which live in the database.
func (s *Server) handleListRuntimes(w http.ResponseWriter, _ *http.Request, _ identity.Principal) {
	runtimes := s.Agents.Runtimes()
	if runtimes == nil {
		runtimes = []agents.Runtime{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"runtimes": runtimes})
}

func (s *Server) handleReleaseName(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request")
		return
	}
	err := s.Identity.ReleaseName(r.Context(), audit.ActorUser(p.UserID), req.Name)
	if errors.Is(err, identity.ErrInvalidName) {
		writeError(w, http.StatusNotFound, "not_found", "no such sign-in name")
		return
	}
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "released"})
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	users, err := s.Directory.ListUsers(r.Context(), r.URL.Query().Get("q"), adminUserLimit)
	if err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) handleSetUserStatus(status string) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, p identity.Principal) {
		err := s.Identity.SetUserStatus(r.Context(), audit.ActorUser(p.UserID), r.PathValue("user"), status)
		switch {
		case errors.Is(err, identity.ErrUserNotFound):
			writeError(w, http.StatusNotFound, "not_found", "no such user")
		case errors.Is(err, identity.ErrPlatformAdminUser):
			writeError(w, http.StatusConflict, "platform_admin", "remove the platform role first")
		case err != nil:
			writeInternal(w, r, err)
		default:
			writeJSON(w, http.StatusOK, map[string]string{"status": status})
		}
	}
}

func (s *Server) handleAddPlatformAdmin(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	if err := s.Directory.AddPlatformAdmin(r.Context(), audit.ActorUser(p.UserID), r.PathValue("user")); err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"platform_admin": true})
}

func (s *Server) handleRemovePlatformAdmin(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	if err := s.Directory.RemovePlatformAdmin(r.Context(), audit.ActorUser(p.UserID), r.PathValue("user")); err != nil {
		writeDirectoryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"platform_admin": false})
}

func writeDirectoryError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, directory.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such tenant, user or unit")
	case errors.Is(err, directory.ErrExists):
		writeError(w, http.StatusConflict, "conflict", "already exists")
	case errors.Is(err, directory.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid value")
	case errors.Is(err, directory.ErrLastAdmin):
		writeError(w, http.StatusConflict, "last_admin", "a tenant needs at least one active admin")
	case errors.Is(err, directory.ErrCycle):
		writeError(w, http.StatusConflict, "cycle", "that would put someone or a unit under itself")
	case errors.Is(err, directory.ErrUnitInUse):
		writeError(w, http.StatusConflict, "unit_in_use", "the unit still has members or child units")
	case errors.Is(err, directory.ErrLastPlatformAdmin):
		writeError(w, http.StatusConflict, "last_platform_admin", "the platform needs at least one admin")
	case errors.Is(err, directory.ErrUserSuspended):
		writeError(w, http.StatusConflict, "user_suspended", "reactivate the user first")
	default:
		writeInternal(w, r, err)
	}
}
