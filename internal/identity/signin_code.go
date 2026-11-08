package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"t10-auth-server/internal/audit"
)

const signInCodeAudience = "t10:signin-code"

// signInCodeTTL is how long someone has to type a code after their password.
const signInCodeTTL = 5 * time.Minute

// StartSignInCode remembers that the password was right, so the page can ask for
// the code alone. It is good for nothing without a valid code.
func (s *Service) StartSignInCode(ctx context.Context, name string) (string, error) {
	c, err := s.lookupByName(ctx, name)
	if err != nil {
		return "", fmt.Errorf("find account: %w", err)
	}
	token, _, err := s.issuer.sign(c.userID, []string{signInCodeAudience}, signInCodeTTL, Claims{})
	return token, err
}

// FinishSignInCode checks the code for a sign-in whose password was already right.
// Limits and lockout are the same as for a code sent with the password.
func (s *Service) FinishSignInCode(ctx context.Context, ticket, code, ip string) (string, error) {
	claims, err := s.issuer.verify(ticket, jwt.WithAudience(signInCodeAudience))
	if err != nil || claims.Subject == "" {
		return "", ErrSignInCodeExpired
	}
	userID := claims.Subject
	if err := s.allowIP(ctx, "signin:ip", ip, s.limits.SignInIP); err != nil {
		return "", err
	}
	if err := s.allowAccount(ctx, "signin:acct", userID, s.limits.SignInAccount); err != nil {
		return "", err
	}
	c, err := s.lookupByID(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("load credential: %w", err)
	}
	actor := audit.ActorUser(userID)
	if c.status != "active" || (c.lockedUntil != nil && c.lockedUntil.After(time.Now())) {
		s.deny(ctx, actor, userID, "locked")
		return "", ErrInvalidCredentials
	}
	valid, err := s.verifyTOTP(ctx, userID, code)
	if err != nil {
		return "", err
	}
	if !valid {
		s.recordFailure(ctx, userID)
		s.deny(ctx, actor, userID, "wrong_totp")
		return "", ErrInvalidCredentials
	}
	return userID, s.clearFailures(ctx, userID)
}

// ErrSignInCodeExpired means the wait for a code ran out, so the password is needed again.
var ErrSignInCodeExpired = errors.New("sign-in code step expired")
