package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"t10-auth-server/internal/agents"
	"t10-auth-server/internal/directory"
	"t10-auth-server/internal/identity"
)

func caller(p identity.Principal) agents.Caller {
	return agents.Caller{ID: p.Service.ID, Name: p.Service.Name}
}

func writeGrantError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, agents.ErrGrantExpired):
		// Only the runtime or a listed service sees this: the run should pause
		// and ask the user to renew, rather than stop.
		writeError(w, http.StatusBadRequest, "grant_expired", "grant has expired")
	case errors.Is(err, agents.ErrGrantInvalid), errors.Is(err, directory.ErrTenantDenied):
		writeError(w, http.StatusBadRequest, "invalid_grant", "grant is invalid or revoked")
	case errors.Is(err, agents.ErrGrantRequest), errors.Is(err, agents.ErrNoTenant):
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
	default:
		writeInternal(w, r, err)
	}
}

// handleGrantExchange is the agent_grant token request. The runtime proves
// itself with its secret, and the grant does the rest.
func (s *Server) handleGrantExchange(w http.ResponseWriter, r *http.Request, req tokenRequest) {
	account, err := s.Identity.ServiceLogin(r.Context(), req.ClientID, req.ClientSecret)
	if errors.Is(err, identity.ErrInvalidClient) {
		writeError(w, http.StatusUnauthorized, "invalid_client", "unknown service or wrong secret")
		return
	}
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	token, expires, grant, err := s.Agents.Exchange(r.Context(), agents.Caller{ID: account.ID, Name: account.Name}, req.GrantID)
	if err != nil {
		writeGrantError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(expires).Seconds()),
		"user_id":      grant.UserID,
		"tenant_id":    grant.TenantID,
		"grant_id":     grant.ID,
		"trigger":      grant.Trigger,
	})
}

// grantTypeTokenExchange is RFC 8693's token exchange.
const grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

// handleTokenExchange is the tool gateway's: it trades a run's token, which only
// the gateway accepts, for one the module it forwards to accepts, with the same
// person, runtime, grant and trigger.
func (s *Server) handleTokenExchange(w http.ResponseWriter, r *http.Request, req tokenRequest) {
	account, err := s.Identity.ServiceLogin(r.Context(), req.ClientID, req.ClientSecret)
	if errors.Is(err, identity.ErrInvalidClient) {
		writeError(w, http.StatusUnauthorized, "invalid_client", "unknown service or wrong secret")
		return
	}
	if err != nil {
		writeInternal(w, r, err)
		return
	}
	subject, err := s.Issuer.VerifyDelegated(req.SubjectToken)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_grant", "subject token is invalid or expired")
		return
	}
	token, expires, err := s.Agents.TokenExchange(r.Context(), agents.Caller{ID: account.ID, Name: account.Name},
		subject.Grant, subject.Audience, subject.ExpiresAt.Time, req.Audience)
	if err != nil {
		writeGrantError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":      token,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        "Bearer",
		"expires_in":        int(time.Until(expires).Seconds()),
	})
}

// handleCreateGrant creates a root grant from a live user token, a child from a
// delegated one, or a firing from a standing grant's ID. The runtime holds the token: model output supplies nothing
// here, and the user and tenant come only from the token.
func (s *Server) handleCreateGrant(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		SubjectToken string          `json:"subject_token"`
		ParentID     string          `json:"parent_id"`
		Actions      []string        `json:"actions"`
		Audiences    []string        `json:"audiences"`
		Constraints  json.RawMessage `json:"constraints"`
		TTLSeconds   int             `json:"ttl_seconds"`
		Standing     bool            `json:"standing"`
		Trigger      string          `json:"trigger"`
		Automation   string          `json:"automation"`
		// Principal names an agent account for a standing grant: the tenant's
		// consent, given with a tenant admin's live token.
		Principal string `json:"principal"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed grant request")
		return
	}
	asked := agents.GrantRequest{
		Actions: req.Actions, Audiences: req.Audiences, Constraints: req.Constraints,
		TTL: time.Duration(req.TTLSeconds) * time.Second, Standing: req.Standing, Trigger: req.Trigger, Automation: req.Automation,
	}
	var grant *agents.Grant
	var err error
	if req.ParentID != "" && req.SubjectToken == "" {
		// A firing: the parent is a standing grant, which mints no token.
		grant, err = s.Agents.CreateFiring(r.Context(), caller(p), req.ParentID, asked)
	} else if delegated, verifyErr := s.Issuer.VerifyDelegated(req.SubjectToken); verifyErr == nil {
		grant, err = s.Agents.CreateChild(r.Context(), caller(p), delegated.Grant, asked)
	} else {
		user, authErr := s.Identity.Authenticate(r.Context(), req.SubjectToken)
		if authErr != nil {
			writeSubjectError(w, r, authErr)
			return
		}
		if req.Principal != "" && req.Principal != user.UserID {
			// Checked live, as every admin route is: a token says who, not what they may do now.
			admin, adminErr := s.Directory.IsTenantAdmin(r.Context(), user.UserID, user.TenantID)
			if adminErr != nil {
				writeInternal(w, r, adminErr)
				return
			}
			if !admin {
				writeError(w, http.StatusForbidden, "forbidden", "only a tenant admin can consent for an agent account")
				return
			}
			grant, err = s.Agents.CreateAgentStanding(r.Context(), caller(p), user.UserID, user.TenantID, req.Principal, asked)
		} else {
			grant, err = s.Agents.CreateRoot(r.Context(), caller(p), user.UserID, user.TenantID, asked)
		}
	}
	if err != nil {
		writeGrantError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, grant)
}

func writeSubjectError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, identity.ErrInvalidToken) {
		writeError(w, http.StatusBadRequest, "invalid_grant", "subject token is invalid or expired")
		return
	}
	writeInternal(w, r, err)
}

func (s *Server) handleGrantChain(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	chain, err := s.Agents.Chain(r.Context(), caller(p), r.PathValue("id"))
	if err != nil {
		writeGrantError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"chain": chain})
}

// handleExtendGrant renews a grant for a new user request. Only a live token of
// the grant's own user can do this.
func (s *Server) handleExtendGrant(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	var req struct {
		SubjectToken string `json:"subject_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request")
		return
	}
	user, err := s.Identity.Authenticate(r.Context(), req.SubjectToken)
	if err != nil {
		writeSubjectError(w, r, err)
		return
	}
	grant, err := s.Agents.Extend(r.Context(), caller(p), r.PathValue("id"), user.UserID, user.TenantID)
	if err != nil {
		writeGrantError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, grant)
}

func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	if err := s.Agents.Revoke(r.Context(), caller(p), r.PathValue("id")); err != nil {
		writeGrantError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
