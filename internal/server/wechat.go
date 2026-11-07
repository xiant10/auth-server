package server

import (
	"net/http"
	"time"

	"t10-auth-server/internal/identity"
)

func writeWeChatTokens(w http.ResponseWriter, tokens identity.DeviceTokens) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"access_token": tokens.Access,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(tokens.ExpiresAt).Seconds()),
		"session_id":   tokens.SessionID,
		"tenant":       tokens.TenantID,
	})
}

func (s *Server) handleWeChatSignIn(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	var req struct {
		ClientID string `json:"client_id"`
		Code     string `json:"code"`
		Name     string `json:"name"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
		Tenant   string `json:"tenant"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Code == "" || req.Name == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "code, name and password are required")
		return
	}
	tokens, err := s.Identity.SignInWeChat(r.Context(), identity.WeChatSignIn{
		ClientID: req.ClientID, Code: req.Code, Name: req.Name, Password: req.Password, TOTP: req.TOTP, Tenant: req.Tenant, IP: s.clientIP(r),
	})
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	writeWeChatTokens(w, tokens)
}

type wechatSessionRequest struct {
	ClientID  string `json:"client_id"`
	SessionID string `json:"session_id"`
	Code      string `json:"code"`
	Tenant    string `json:"tenant"`
}

func (s *Server) handleWeChatRefresh(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	var req wechatSessionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	tokens, err := s.Identity.RefreshWeChat(r.Context(), identity.WeChatRefresh{ClientID: req.ClientID, SessionID: req.SessionID, Code: req.Code, Tenant: req.Tenant, IP: s.clientIP(r)})
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	writeWeChatTokens(w, tokens)
}

func (s *Server) handleWeChatSignOut(w http.ResponseWriter, r *http.Request, _ identity.Principal) {
	var req wechatSessionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	err := s.Identity.SignOutWeChat(r.Context(), identity.WeChatRefresh{ClientID: req.ClientID, SessionID: req.SessionID, Code: req.Code, IP: s.clientIP(r)})
	if err != nil {
		writeMobileError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
