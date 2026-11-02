package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Signature purposes. Each signed message names one, so a signature made for
// one operation can never stand in for another.
const (
	PurposeLogin    = "login"
	PurposeRegister = "register"
	PurposePair     = "pair"
	PurposeRefresh  = "refresh"
	PurposeApprove  = "approve"
	PurposeReauth   = "reauth"

	challengeTTL  = 2 * time.Minute
	signedPreface = "t10-device-v1"
)

// Device errors.
var (
	ErrInvalidDevice          = errors.New("invalid device key or signature")
	ErrInvalidChallenge       = errors.New("challenge is unknown, used or expired")
	ErrDeviceRevoked          = errors.New("device is revoked")
	ErrDeviceApprovalRequired = errors.New("a new device needs approval from an enrolled one, or a second factor")
)

// DeviceInfo is what an app reports when it enrolls. Keys are base64url P-256
// public keys, as SPKI DER (Android) or an uncompressed X9.63 point (iOS).
type DeviceInfo struct {
	Name              string `json:"name"`
	Platform          string `json:"platform"`
	ApprovalPublicKey string `json:"approval_public_key"`
	SessionPublicKey  string `json:"session_public_key"`
}

// decodeB64 takes base64url or standard base64, padded or not, because the
// platforms' default encoders differ.
func decodeB64(value string) ([]byte, error) {
	clean := strings.NewReplacer("+", "-", "/", "_").Replace(strings.TrimRight(value, "="))
	return base64.RawURLEncoding.DecodeString(clean)
}

// parsePublicKey returns the key as an uncompressed point.
func parsePublicKey(encoded string) ([]byte, error) {
	der, err := decodeB64(encoded)
	if err != nil {
		return nil, ErrInvalidDevice
	}
	var public *ecdsa.PublicKey
	if len(der) == 65 && der[0] == 4 {
		public, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), der)
		if err != nil {
			return nil, ErrInvalidDevice
		}
	} else {
		parsed, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, ErrInvalidDevice
		}
		var ok bool
		if public, ok = parsed.(*ecdsa.PublicKey); !ok || public.Curve != elliptic.P256() {
			return nil, ErrInvalidDevice
		}
	}
	point, err := public.Bytes()
	if err != nil {
		return nil, ErrInvalidDevice
	}
	return point, nil
}

type parsedDevice struct {
	name, platform    string
	approval, session []byte
}

func parseDevice(info DeviceInfo) (parsedDevice, error) {
	if info.Platform != "ios" && info.Platform != "android" {
		return parsedDevice{}, ErrInvalidDevice
	}
	name := strings.TrimSpace(info.Name)
	if name == "" || len(name) > 100 {
		return parsedDevice{}, ErrInvalidDevice
	}
	approval, err := parsePublicKey(info.ApprovalPublicKey)
	if err != nil {
		return parsedDevice{}, err
	}
	session, err := parsePublicKey(info.SessionPublicKey)
	if err != nil {
		return parsedDevice{}, err
	}
	if string(approval) == string(session) {
		return parsedDevice{}, ErrInvalidDevice
	}
	return parsedDevice{name: name, platform: info.Platform, approval: approval, session: session}, nil
}

// KeyBinding identifies a key inside a signed message: the hex SHA-256 of the
// key as an uncompressed point.
func KeyBinding(point []byte) string {
	sum := sha256.Sum256(point)
	return hex.EncodeToString(sum[:])
}

// SignedMessage is the exact byte string an app signs with ECDSA over SHA-256.
func SignedMessage(purpose, challenge, binding string) []byte {
	return []byte(signedPreface + "\n" + purpose + "\n" + challenge + "\n" + binding)
}

// verifySignature checks a base64 ASN.1 DER signature, which is what both the
// Secure Enclave and Android Keystore produce.
func verifySignature(point, message []byte, signature string) bool {
	public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return false
	}
	der, err := decodeB64(signature)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(message)
	return ecdsa.VerifyASN1(public, digest[:], der)
}

// IssueChallenge creates a single-use nonce for one purpose.
func (s *Service) IssueChallenge(ctx context.Context, purpose, ip string) (string, time.Time, error) {
	switch purpose {
	case PurposeLogin, PurposeRegister, PurposePair, PurposeRefresh, PurposeApprove, PurposeReauth:
	default:
		return "", time.Time{}, ErrInvalidChallenge
	}
	if err := s.allowIP(ctx, "challenge:ip", ip, s.limits.ChallengeIP); err != nil {
		return "", time.Time{}, err
	}
	challenge := randomSecret()
	expires := time.Now().Add(challengeTTL)
	_, err := s.pool.Exec(ctx,
		"INSERT INTO auth.device_challenges (challenge_hash, purpose, expires_at) VALUES ($1, $2, $3)",
		hashSecret(challenge), purpose, expires)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("store challenge: %w", err)
	}
	return challenge, expires, nil
}

func (s *Service) consumeChallenge(ctx context.Context, purpose, challenge string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE auth.device_challenges SET used_at = now()
		 WHERE challenge_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > now()`,
		hashSecret(challenge), purpose)
	if err != nil {
		return fmt.Errorf("spend challenge: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrInvalidChallenge
	}
	return nil
}

// verifyEnrollmentProof spends a challenge and checks the session key's
// signature, which shows the caller holds the key it wants to enroll.
func (s *Service) verifyEnrollmentProof(ctx context.Context, purpose string, d parsedDevice, challenge, signature string) error {
	if err := s.consumeChallenge(ctx, purpose, challenge); err != nil {
		return err
	}
	if !verifySignature(d.session, SignedMessage(purpose, challenge, KeyBinding(d.session)), signature) {
		return ErrInvalidDevice
	}
	return nil
}

// DeviceProof is a fresh signature by a device's approval key, which the
// device releases only after a biometric or passcode check.
type DeviceProof struct {
	DeviceID  string
	Challenge string
	Signature string
}

// Reauth is how a user proves themselves again before a sensitive change: the
// current password and any enrolled factor, or a fresh device proof.
type Reauth struct {
	Password string
	Code     string
	Device   *DeviceProof
}

// checkReauth applies a Reauth to one named action. A device signature covers
// the action, so it cannot be replayed for a different change.
func (s *Service) checkReauth(ctx context.Context, userID, action string, r Reauth) error {
	if r.Device == nil {
		c, err := s.lookupByID(ctx, userID)
		if err != nil {
			return err
		}
		_, err = s.checkSecrets(ctx, c, r.Password, r.Code)
		return err
	}
	approval, _, err := s.approvalKey(ctx, userID, r.Device.DeviceID)
	if err != nil {
		return err
	}
	if err := s.consumeChallenge(ctx, PurposeReauth, r.Device.Challenge); err != nil {
		return err
	}
	if !verifySignature(approval, SignedMessage(PurposeReauth, r.Device.Challenge, r.Device.DeviceID+"\n"+action), r.Device.Signature) {
		s.deny(ctx, "user:"+userID, userID, "bad_device_proof")
		return ErrInvalidDevice
	}
	return nil
}

func (s *Service) approvalKey(ctx context.Context, userID, deviceID string) (key []byte, mfaCapable bool, err error) {
	err = s.pool.QueryRow(ctx,
		"SELECT approval_public_key, mfa_capable FROM auth.devices WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
		deviceID, userID).Scan(&key, &mfaCapable)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, ErrDeviceRevoked
	}
	if err != nil {
		return nil, false, fmt.Errorf("load device: %w", err)
	}
	return key, mfaCapable, nil
}
