package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// ErrRateLimited means a caller has used up a limit.
var ErrRateLimited = errors.New("too many attempts")

// Limit allows Max events per fixed Window.
type Limit struct {
	Max    int
	Window time.Duration
}

// Limits apply per IP and per account, to web pages and any later API alike.
type Limits struct {
	SignInIP       Limit
	SignInAccount  Limit
	RegisterIP     Limit
	RecoverIP      Limit
	RecoverAccount Limit
	ChallengeIP    Limit
	QRIP           Limit
}

// DefaultLimits are the production values.
func DefaultLimits() Limits {
	return Limits{
		SignInIP:       Limit{Max: 30, Window: time.Minute},
		SignInAccount:  Limit{Max: 20, Window: 15 * time.Minute},
		RegisterIP:     Limit{Max: 10, Window: time.Hour},
		RecoverIP:      Limit{Max: 10, Window: 15 * time.Minute},
		RecoverAccount: Limit{Max: 5, Window: 15 * time.Minute},
		ChallengeIP:    Limit{Max: 120, Window: time.Minute},
		QRIP:           Limit{Max: 30, Window: time.Minute},
	}
}

// allow counts one event. A storage failure refuses it, so limits fail closed.
func (s *Service) allow(ctx context.Context, key string, l Limit) error {
	secs := int(l.Window.Seconds())
	var count int
	err := s.pool.QueryRow(ctx,
		`INSERT INTO auth.rate_limits (key, window_start, count)
		 VALUES ($1, to_timestamp(floor(extract(epoch FROM now()) / $2) * $2), 1)
		 ON CONFLICT (key, window_start) DO UPDATE SET count = auth.rate_limits.count + 1
		 RETURNING count`, key, secs).Scan(&count)
	if err != nil {
		return fmt.Errorf("rate limit: %w", err)
	}
	if count > l.Max {
		return ErrRateLimited
	}
	return nil
}

// allowIP limits by client address.
func (s *Service) allowIP(ctx context.Context, prefix, ip string, l Limit) error {
	return s.allow(ctx, prefix+":"+ipKey(ip), l)
}

// ipKey counts IPv6 by /64, the block one subscriber usually holds, or rotating
// addresses inside it would dodge every limit.
func ipKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is6() {
		prefix, err := addr.Prefix(64)
		if err != nil {
			return ip
		}
		return prefix.String()
	}
	return addr.String()
}

// allowAccount limits by name, in its stored form so that respelling a phone
// number does not restart the count. The name is hashed first, because people
// type passwords into that box.
func (s *Service) allowAccount(ctx context.Context, prefix, name string, l Limit) error {
	key := strings.ToLower(strings.TrimSpace(name))
	if _, value, err := NormalizeName(name, s.region); err == nil {
		key = value
	}
	sum := sha256.Sum256([]byte(key))
	return s.allow(ctx, prefix+":"+hex.EncodeToString(sum[:]), l)
}

// AllowRegistration counts one registration attempt from ip.
func (s *Service) AllowRegistration(ctx context.Context, ip string) error {
	return s.allowIP(ctx, "register:ip", ip, s.limits.RegisterIP)
}

// Purge removes expired short-lived rows. Audit and session rows stay.
func (s *Service) Purge(ctx context.Context) error {
	for _, stmt := range []string{
		"DELETE FROM auth.rate_limits WHERE window_start < now() - interval '1 day'",
		"DELETE FROM auth.auth_codes WHERE expires_at < now() - interval '1 day'",
		"DELETE FROM auth.reset_tokens WHERE expires_at < now() - interval '1 day'",
		"DELETE FROM auth.device_challenges WHERE expires_at < now() - interval '1 day'",
		"DELETE FROM auth.mfa_challenges WHERE expires_at < now() - interval '1 day'",
		"DELETE FROM auth.qr_logins WHERE expires_at < now() - interval '1 day'",
	} {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("purge: %w", err)
		}
	}
	return nil
}
