package identity

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

const browserLogoutAudience = "t10:browser-logout"

// MintBrowserLogout authorizes only ending this user's browser session. It is
// deliberately not an access token and cannot authorize API requests.
func (i *Issuer) MintBrowserLogout(userID, redirect string) (string, error) {
	token, _, err := i.sign(userID, []string{browserLogoutAudience}, time.Minute, Claims{LogoutRedirect: redirect})
	return token, err
}

func (i *Issuer) VerifyBrowserLogout(raw string) (*Claims, error) {
	return i.verify(raw, jwt.WithAudience(browserLogoutAudience))
}
