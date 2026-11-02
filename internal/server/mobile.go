package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	qrcode "github.com/skip2/go-qrcode"

	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/identity"
)

// decodeJSON reads a request body, refusing unknown fields so a mistyped field
// fails in integration instead of being ignored.
func decodeJSON(w http.ResponseWriter, r *http.Request, into any) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return false
	}
	return true
}

// writeMobileError gives each failure one stable code. docs/openapi.yaml lists
// them, and clients branch on the code, never the description.
func writeMobileError(w http.ResponseWriter, r *http.Request, err error) {
	type mapping struct {
		target error
		status int
		code   string
		text   string
	}
	for _, m := range []mapping{
		{identity.ErrInvalidCredentials, http.StatusUnauthorized, "invalid_credentials", "wrong sign-in name, password or code"},
		{identity.ErrInvalidDisplayName, http.StatusBadRequest, "invalid_display_name", "a name needs 1 to 100 characters"},
		{identity.ErrInvalidClient, http.StatusUnauthorized, "invalid_client", "this client may not use this API"},
		{identity.ErrInvalidGrant, http.StatusBadRequest, "invalid_grant", "token or session is invalid or expired"},
		{identity.ErrInvalidDevice, http.StatusBadRequest, "invalid_device", "bad device key or signature"},
		{identity.ErrInvalidChallenge, http.StatusBadRequest, "invalid_challenge", "challenge is unknown, used or expired"},
		{identity.ErrDeviceRevoked, http.StatusForbidden, "device_revoked", "this device is revoked; generate new keys"},
		{identity.ErrDeviceApprovalRequired, http.StatusForbidden, "device_approval_required", "approve from an enrolled device, or use a second factor"},
		{identity.ErrQRInvalid, http.StatusBadRequest, "qr_invalid", "this QR request is invalid, taken or expired"},
		{identity.ErrRateLimited, http.StatusTooManyRequests, "rate_limited", "too many attempts"},
		{identity.ErrMFARequired, http.StatusForbidden, "mfa_required", "a second factor is required"},
		{identity.ErrMFAMandatory, http.StatusForbidden, "mfa_mandatory", "this account must keep a second factor"},
		{identity.ErrTOTPEnrolled, http.StatusConflict, "totp_enrolled", "an authenticator is already on"},
		{identity.ErrInvalidName, http.StatusBadRequest, "invalid_name", "not a valid username, phone number or email"},
		{identity.ErrNameTaken, http.StatusConflict, "name_taken", "that sign-in name is taken"},
		{identity.ErrLastName, http.StatusBadRequest, "last_name", "an account needs at least one sign-in name"},
		{identity.ErrWeakPassword, http.StatusBadRequest, "weak_password", "use a longer, less common password of at least 10 characters"},
		{directory.ErrInvitationInvalid, http.StatusBadRequest, "invitation_invalid", "this invitation is invalid, used or expired"},
		{directory.ErrExists, http.StatusConflict, "already_member", "already a member of this tenant"},
		{directory.ErrTenantDenied, http.StatusForbidden, "tenant_denied", "no active membership in that tenant"},
		{directory.ErrNoTenant, http.StatusForbidden, "tenant_denied", "no active tenant"},
	} {
		if errors.Is(err, m.target) {
			writeError(w, m.status, m.code, m.text)
			return
		}
	}
	writeInternal(w, r, err)
}

func writeDeviceTokens(w http.ResponseWriter, tokens identity.DeviceTokens) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"access_token": tokens.Access,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(tokens.ExpiresAt).Seconds()),
		"session_id":   tokens.SessionID,
		"device_id":    tokens.DeviceID,
		"tenant":       tokens.TenantID,
	})
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	var req struct {
		Purpose string `json:"purpose"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	challenge, expires, err := s.Identity.IssueChallenge(r.Context(), req.Purpose, s.clientIP(r))
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"challenge": challenge, "expires_in": int(time.Until(expires).Seconds())})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	var req struct {
		ClientID  string              `json:"client_id"`
		Name      string              `json:"name"`
		Password  string              `json:"password"`
		Tenant    string              `json:"tenant"`
		Device    identity.DeviceInfo `json:"device"`
		Challenge string              `json:"challenge"`
		Signature string              `json:"signature"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	result, err := s.Identity.Login(r.Context(), identity.DirectLogin{
		ClientID: req.ClientID, Name: req.Name, Password: req.Password, Tenant: req.Tenant,
		Device: req.Device, Challenge: req.Challenge, Signature: req.Signature, IP: s.clientIP(r),
	})
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	if result.Tokens == nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "mfa_required", "mfa_token": result.MFAToken, "expires_in": 300})
		return
	}
	writeDeviceTokens(w, *result.Tokens)
}

func (s *Server) handleLoginMFA(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	var req struct {
		MFAToken string `json:"mfa_token"`
		Code     string `json:"code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	tokens, err := s.Identity.CompleteMFA(r.Context(), req.MFAToken, req.Code)
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	writeDeviceTokens(w, tokens)
}

// handleLoginRegister shares the web page's rules: invitation-only outside dev
// mode, the same limit, and the same account setup.
func (s *Server) handleLoginRegister(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	var req struct {
		ClientID string `json:"client_id"`
		Name     string `json:"name"`
		// DisplayName is optional until mobile clients ask for it.
		DisplayName string              `json:"display_name"`
		Password    string              `json:"password"`
		Invite      string              `json:"invite"`
		Device      identity.DeviceInfo `json:"device"`
		Challenge   string              `json:"challenge"`
		Signature   string              `json:"signature"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	if req.Invite == "" && !s.DevMode {
		writeError(w, http.StatusForbidden, "registration_closed", "registration needs an invitation")
		return
	}
	if err := s.Identity.AllowRegistration(ctx, s.clientIP(r)); err != nil {
		writeMobileError(w, r, err)
		return
	}
	if err := s.Identity.VerifyDeviceSignup(ctx, req.ClientID, req.Device, req.Challenge, req.Signature); err != nil {
		writeMobileError(w, r, err)
		return
	}
	userID, codes, err := s.registerAccount(ctx, req.Name, req.DisplayName, req.Password, req.Invite)
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	tokens, err := s.Identity.EnrollFirstDevice(ctx, req.ClientID, userID, req.Device)
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"access_token":   tokens.Access,
		"token_type":     "Bearer",
		"expires_in":     int(time.Until(tokens.ExpiresAt).Seconds()),
		"session_id":     tokens.SessionID,
		"device_id":      tokens.DeviceID,
		"tenant":         tokens.TenantID,
		"recovery_codes": codes,
	})
}

func (s *Server) handleLoginRecover(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	var req struct {
		Name         string `json:"name"`
		RecoveryCode string `json:"recovery_code"`
		SecondCode   string `json:"second_code"`
		Code         string `json:"code"`
		NewPassword  string `json:"new_password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	err := s.Identity.Recover(r.Context(), identity.Recovery{
		Name: req.Name, Code: req.RecoveryCode, SecondCode: req.SecondCode, TOTP: req.Code,
		NewPassword: req.NewPassword, IP: s.clientIP(r),
	})
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) qrPayload(id string) string {
	return s.PublicURL + "/v1/qr/" + id
}

// handlePair starts a second device's enrollment. The new device shows the
// payload as a QR code for an enrolled device to scan.
func (s *Server) handlePair(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	var req struct {
		ClientID  string              `json:"client_id"`
		Device    identity.DeviceInfo `json:"device"`
		Challenge string              `json:"challenge"`
		Signature string              `json:"signature"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	ticket, err := s.Identity.StartPairing(r.Context(), req.ClientID, req.Device, req.Challenge, req.Signature,
		s.clientIP(r), r.UserAgent())
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"qr_payload": s.qrPayload(ticket.ID),
		"poll_token": ticket.Poll,
		"expires_in": int(time.Until(ticket.ExpiresAt).Seconds()),
	})
}

func (s *Server) handlePairPoll(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	var req struct {
		PollToken string `json:"poll_token"`
		Tenant    string `json:"tenant"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	result, err := s.Identity.PollQR(r.Context(), identity.QRDevice, req.PollToken)
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	if result.Status != identity.QRApproved {
		writeJSON(w, http.StatusOK, map[string]string{"status": result.Status})
		return
	}
	tokens, err := s.Identity.CollectPairing(r.Context(), result, req.Tenant)
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	writeDeviceTokens(w, tokens)
}

func (s *Server) qrCookieName() string {
	if s.secureCookies() {
		return "__Host-t10_qr"
	}
	return "t10_qr"
}

func (s *Server) setQRCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: s.qrCookieName(), Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.secureCookies(), SameSite: http.SameSiteStrictMode,
	})
}

// handleQRStart gives the sign-in page a code. The poll secret stays in an
// HttpOnly cookie, so a person who photographs the screen gets nothing usable.
func (s *Server) handleQRStart(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	var req struct {
		Next string `json:"next"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	clientID := "browser"
	if u, err := url.Parse(safeNext(req.Next)); err == nil && u.Path == "/v1/authorize" {
		if _, ok := s.Identity.Client(u.Query().Get("client_id")); ok {
			clientID = u.Query().Get("client_id")
		}
	}
	ticket, err := s.Identity.StartQRLogin(r.Context(), clientID, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	png, err := qrcode.Encode(s.qrPayload(ticket.ID), qrcode.Medium, 440)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	lifetime := int(time.Until(ticket.ExpiresAt).Seconds())
	s.setQRCookie(w, ticket.Poll, lifetime)
	writeJSON(w, http.StatusOK, map[string]any{
		"image":      "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
		"expires_in": lifetime,
	})
}

// handleQRPoll turns an approval into a browser session, then the page goes on
// to next, so a client's normal code flow finishes the sign-in.
func (s *Server) handleQRPoll(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	cookie, err := r.Cookie(s.qrCookieName())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": identity.QRExpired})
		return
	}
	result, err := s.Identity.PollQR(r.Context(), identity.QRLogin, cookie.Value)
	if errors.Is(err, identity.ErrQRInvalid) {
		writeJSON(w, http.StatusOK, map[string]string{"status": identity.QRExpired})
		return
	}
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	if result.Status == identity.QRApproved {
		if !s.startBrowserSession(w, r, result.UserID, result.MFA) {
			return
		}
		s.setQRCookie(w, "", -1)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": result.Status})
}

func (s *Server) handleQRClaim(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	request, err := s.Identity.ClaimQR(r.Context(), p.UserID, p.DeviceID, r.PathValue("id"))
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"kind":         request.Kind,
		"client_id":    request.ClientID,
		"client_name":  request.ClientName,
		"requester_ip": request.RequesterIP,
		"user_agent":   request.UserAgent,
		"device_name":  request.DeviceName,
		"expires_in":   int(time.Until(request.ExpiresAt).Seconds()),
	})
}

type signedProof struct {
	Challenge string `json:"challenge"`
	Signature string `json:"signature"`
}

func (s *Server) handleQRApprove(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req signedProof
	if !decodeJSON(w, r, &req) {
		return
	}
	err := s.Identity.ApproveQR(r.Context(), p.UserID, p.DeviceID, r.PathValue("id"), req.Challenge, req.Signature)
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": identity.QRApproved})
}

func (s *Server) handleQRDeny(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	if err := s.Identity.DenyQR(r.Context(), p.UserID, p.DeviceID, r.PathValue("id")); err != nil {
		writeMobileError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": identity.QRDenied})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	account, err := s.Identity.GetAccount(r.Context(), p.UserID)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	tenants, err := s.Directory.ListUserTenants(r.Context(), p.UserID)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	names := make([]map[string]any, len(account.Names))
	for i, n := range account.Names {
		names[i] = map[string]any{"kind": n.Kind, "value": n.Value, "verified": false}
	}
	devices := make([]map[string]any, len(account.Devices))
	for i, d := range account.Devices {
		devices[i] = map[string]any{
			"id": d.ID, "name": d.Name, "platform": d.Platform, "last_used_at": d.LastUsedAt,
			"created_at": d.CreatedAt, "current": d.ID == p.DeviceID,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":             p.UserID,
		"display_name":        account.DisplayName,
		"active_tenant":       p.TenantID,
		"tenants":             tenants,
		"names":               names,
		"totp_enabled":        account.TOTP,
		"recovery_codes_left": account.RecoveryCodes,
		"devices":             devices,
	})
}

func (s *Server) handleUpdateMe(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		DisplayName string `json:"display_name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.Identity.SetDisplayName(r.Context(), p.UserID, req.DisplayName); err != nil {
		writeMobileError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	if err := s.Identity.EndSession(r.Context(), p.UserID, p.SessionID); err != nil {
		writeInternal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func deviceReauth(p identity.Principal, proof signedProof) identity.Reauth {
	return identity.Reauth{Device: &identity.DeviceProof{DeviceID: p.DeviceID, Challenge: proof.Challenge, Signature: proof.Signature}}
}

func (s *Server) respondOK(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMePassword(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		signedProof
		NewPassword string `json:"new_password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	s.respondOK(w, r, s.Identity.ChangePassword(r.Context(), p.UserID, p.SessionID, req.NewPassword, deviceReauth(p, req.signedProof)))
}

func (s *Server) handleMeAddName(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		signedProof
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	s.respondOK(w, r, s.Identity.AddName(r.Context(), p.UserID, req.Name, deviceReauth(p, req.signedProof)))
}

func (s *Server) handleMeRemoveName(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		signedProof
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	kind, value, err := s.Identity.Normalize(req.Name)
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	s.respondOK(w, r, s.Identity.RemoveName(r.Context(), p.UserID, kind, value, deviceReauth(p, req.signedProof)))
}

func (s *Server) handleMeTOTPStart(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req signedProof
	if !decodeJSON(w, r, &req) {
		return
	}
	account, err := s.Identity.GetAccount(r.Context(), p.UserID)
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	enrollment, err := s.Identity.StartTOTP(r.Context(), p.UserID, account.Label(), deviceReauth(p, req))
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": enrollment.Secret, "otpauth_url": enrollment.URL})
}

func (s *Server) handleMeTOTPConfirm(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	s.respondOK(w, r, s.Identity.ConfirmTOTP(r.Context(), p.UserID, p.SessionID, req.Code))
}

func (s *Server) handleMeTOTPDisable(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req signedProof
	if !decodeJSON(w, r, &req) {
		return
	}
	s.respondOK(w, r, s.Identity.DisableTOTP(r.Context(), p.UserID, deviceReauth(p, req)))
}

func (s *Server) handleMeRecoveryCodes(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req signedProof
	if !decodeJSON(w, r, &req) {
		return
	}
	codes, err := s.Identity.RegenerateRecoveryCodes(r.Context(), p.UserID, deviceReauth(p, req))
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

func (s *Server) handleMeSignOutAll(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	s.respondOK(w, r, s.Identity.SignOutEverywhere(r.Context(), p.UserID))
}

func (s *Server) handleMeAcceptInvitation(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		Invite string `json:"invite"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	var member directory.Member
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var err error
		member, err = s.Directory.AcceptInvitation(ctx, tx, audit.ActorUser(p.UserID), req.Invite, p.UserID)
		return err
	})
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "tenant": member.TenantID})
}

func (s *Server) handleDeviceRevoke(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req signedProof
	if !decodeJSON(w, r, &req) {
		return
	}
	s.respondOK(w, r, s.Identity.RevokeDevice(r.Context(), p.UserID, r.PathValue("id"), deviceReauth(p, req)))
}
