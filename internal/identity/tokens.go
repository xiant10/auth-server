package identity

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"t10-auth-server/internal/agents"
	"t10-auth-server/internal/ids"
)

const (
	// AudienceT10 is the platform audience on every user token.
	AudienceT10 = "t10"
	// ScopeAgentUse is the entry right agent-pi requires.
	ScopeAgentUse = "agent:use"
	// AccessTokenTTL is the lifetime of an access token.
	AccessTokenTTL = 5 * time.Minute
)

// ErrInvalidToken means a bearer token failed verification.
var ErrInvalidToken = errors.New("invalid token")

// Claims is the access token payload.
type Claims struct {
	jwt.RegisteredClaims
	LogoutRedirect string `json:"logout_redirect,omitempty"`
	TenantID       string `json:"tid,omitempty"`
	Scope          string `json:"scope,omitempty"`
	SessionID      string `json:"sid,omitempty"`
	// Actor and Grant appear only on delegated tokens, with Trigger, which says
	// why the run is running, and Automation when one started it.
	Actor      *Actor `json:"act,omitempty"`
	Grant      string `json:"grant,omitempty"`
	Trigger    string `json:"trg,omitempty"`
	Automation string `json:"automation,omitempty"`
}

// Actor names the runtime acting for the user.
type Actor struct {
	Subject string `json:"sub"`
}

// Issuer signs and verifies the service's JWTs.
type Issuer struct {
	url  string
	keys *KeySet
	now  func() time.Time
}

// NewIssuer returns an Issuer for the given public URL.
func NewIssuer(url string, keys *KeySet) *Issuer {
	return &Issuer{url: url, keys: keys, now: time.Now}
}

// JWKS returns the public keys.
func (i *Issuer) JWKS() JWKS { return i.keys.JWKS() }

// MintAccess signs a user access token. tenantID is empty only for a platform
// admin with no membership.
func (i *Issuer) MintAccess(userID, tenantID, sessionID string) (string, time.Time, error) {
	claims := Claims{TenantID: tenantID, Scope: ScopeAgentUse, SessionID: sessionID}
	return i.sign(userID, []string{AudienceT10}, AccessTokenTTL, claims)
}

// SignAssertion signs a token for one audience. The audience must not be one a
// service accepts as a bearer token, which keeps the result out of API use.
func (i *Issuer) SignAssertion(userID, tenantID, audience string, ttl time.Duration) (string, time.Time, error) {
	return i.sign(userID, []string{audience}, ttl, Claims{TenantID: tenantID})
}

// MintService signs a service token. It has no tenant, session or scope, so no
// user route and no agent-pi deployment accepts it.
func (i *Issuer) MintService(serviceID string) (string, time.Time, error) {
	return i.sign(serviceID, []string{AudienceT10}, AccessTokenTTL, Claims{})
}

// MintDelegated signs a token for a grant. Its audience is the grant's services
// and never t10, so it can't be replayed as a user token.
func (i *Issuer) MintDelegated(d agents.Delegation, ttl time.Duration) (string, time.Time, error) {
	claims := Claims{
		TenantID: d.TenantID, Scope: d.Scope, Actor: &Actor{Subject: d.RuntimeID}, Grant: d.GrantID,
		Trigger: d.Trigger, Automation: d.Automation,
	}
	return i.sign(d.UserID, d.Audiences, ttl, claims)
}

func (i *Issuer) sign(subject string, audience []string, ttl time.Duration, claims Claims) (string, time.Time, error) {
	now := i.now()
	expires := now.Add(ttl)
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    i.url,
		Subject:   subject,
		Audience:  audience,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expires),
		ID:        ids.New("jti"),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = i.keys.current.KID
	signed, err := token.SignedString(i.keys.current.private)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign token: %w", err)
	}
	return signed, expires, nil
}

// Verify checks a user access token offline and returns its claims.
func (i *Issuer) Verify(raw string) (*Claims, error) {
	return i.verify(raw, jwt.WithAudience(AudienceT10))
}

// VerifyDelegated checks a token minted from a grant. The audience is left to
// the caller, because the grant decides who may present it.
func (i *Issuer) VerifyDelegated(raw string) (*Claims, error) {
	claims, err := i.verify(raw)
	if err != nil {
		return nil, err
	}
	if claims.Grant == "" || claims.Actor == nil {
		return nil, fmt.Errorf("%w: not a delegated token", ErrInvalidToken)
	}
	return claims, nil
}

func (i *Issuer) verify(raw string, extra ...jwt.ParserOption) (*Claims, error) {
	claims := &Claims{}
	options := append([]jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithIssuer(i.url),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(i.now),
	}, extra...)
	_, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		key := i.keys.byKID(kid)
		if key == nil {
			return nil, errors.New("unknown kid")
		}
		return &key.private.PublicKey, nil
	}, options...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return claims, nil
}
