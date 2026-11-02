package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"t10-auth-server/internal/audit"
)

const qrTTL = 2 * time.Minute

// QR request kinds and statuses.
const (
	QRLogin  = "login"
	QRDevice = "device"

	QRPending  = "pending"
	QRClaimed  = "claimed"
	QRApproved = "approved"
	QRDenied   = "denied"
	QRExpired  = "expired"
)

// ErrQRInvalid means a QR request is unknown, taken, finished or expired.
var ErrQRInvalid = errors.New("QR request is invalid or expired")

// QRTicket is what a requester holds: the public ID the code shows, and the
// private poll secret that collects the result.
type QRTicket struct {
	ID        string
	Poll      string
	ExpiresAt time.Time
}

// StartQRLogin creates a request for a browser sign-in.
func (s *Service) StartQRLogin(ctx context.Context, clientID, ip, userAgent string) (QRTicket, error) {
	return s.createQR(ctx, QRLogin, clientID, ip, userAgent, nil)
}

// StartPairing creates a request for a new device to be approved by an enrolled
// one, after proving it holds the keys it wants enrolled.
func (s *Service) StartPairing(ctx context.Context, clientID string, info DeviceInfo, challenge, signature, ip, userAgent string) (QRTicket, error) {
	if _, err := s.directClient(clientID); err != nil {
		return QRTicket{}, err
	}
	device, err := parseDevice(info)
	if err != nil {
		return QRTicket{}, err
	}
	if err := s.verifyEnrollmentProof(ctx, PurposePair, device, challenge, signature); err != nil {
		return QRTicket{}, err
	}
	pending, err := json.Marshal(info)
	if err != nil {
		return QRTicket{}, fmt.Errorf("encode device: %w", err)
	}
	return s.createQR(ctx, QRDevice, clientID, ip, userAgent, pending)
}

func (s *Service) createQR(ctx context.Context, kind, clientID, ip, userAgent string, pending []byte) (QRTicket, error) {
	if err := s.allowIP(ctx, "qr:ip", ip, s.limits.QRIP); err != nil {
		return QRTicket{}, err
	}
	ticket := QRTicket{ID: randomSecret(), Poll: randomSecret(), ExpiresAt: time.Now().Add(qrTTL)}
	if len(userAgent) > 200 {
		userAgent = strings.ToValidUTF8(userAgent[:200], "")
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO auth.qr_logins (id_hash, poll_hash, kind, client_id, requester_ip, user_agent, pending_device, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		hashSecret(ticket.ID), hashSecret(ticket.Poll), kind, clientID, ip, userAgent, pending, ticket.ExpiresAt)
	if err != nil {
		return QRTicket{}, fmt.Errorf("store QR request: %w", err)
	}
	return ticket, nil
}

// QRRequest is what the app shows before the user approves, so they can spot a
// code that an attacker put in front of them.
type QRRequest struct {
	Kind        string
	ClientID    string
	ClientName  string
	RequesterIP string
	UserAgent   string
	DeviceName  string
	ExpiresAt   time.Time
}

// ClaimQR ties a request to the first enrolled device that scans it, so only
// that device can approve it and no second scan can take it over.
func (s *Service) ClaimQR(ctx context.Context, userID, deviceID, id string) (QRRequest, error) {
	if _, _, err := s.approvalKey(ctx, userID, deviceID); err != nil {
		return QRRequest{}, err
	}
	var r QRRequest
	var pending []byte
	err := s.pool.QueryRow(ctx,
		`UPDATE auth.qr_logins SET status = 'claimed', user_id = $2, device_id = $3
		 WHERE id_hash = $1 AND status = 'pending' AND expires_at > now()
		 RETURNING kind, client_id, requester_ip, user_agent, pending_device, expires_at`,
		hashSecret(id), userID, deviceID).Scan(&r.Kind, &r.ClientID, &r.RequesterIP, &r.UserAgent, &pending, &r.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return QRRequest{}, ErrQRInvalid
	}
	if err != nil {
		return QRRequest{}, fmt.Errorf("claim QR request: %w", err)
	}
	r.ClientName = r.ClientID
	if client, ok := s.Client(r.ClientID); ok && client.Name != "" {
		r.ClientName = client.Name
	}
	if pending != nil {
		var info DeviceInfo
		if err := json.Unmarshal(pending, &info); err != nil {
			return QRRequest{}, fmt.Errorf("decode device: %w", err)
		}
		r.DeviceName = info.Name
	}
	return r, nil
}

// ApproveQR records the user's approval. The approval key unlocks only after a
// biometric or passcode check, and this signature covers this request alone.
func (s *Service) ApproveQR(ctx context.Context, userID, deviceID, id, challenge, signature string) error {
	approval, _, err := s.approvalKey(ctx, userID, deviceID)
	if err != nil {
		return err
	}
	var status string
	err = s.pool.QueryRow(ctx,
		"SELECT status FROM auth.qr_logins WHERE id_hash = $1 AND user_id = $2 AND device_id = $3 AND expires_at > now()",
		hashSecret(id), userID, deviceID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) || status != QRClaimed {
		return ErrQRInvalid
	}
	if err != nil {
		return fmt.Errorf("load QR request: %w", err)
	}
	if err := s.consumeChallenge(ctx, PurposeApprove, challenge); err != nil {
		return err
	}
	if !verifySignature(approval, SignedMessage(PurposeApprove, challenge, id), signature) {
		s.deny(ctx, audit.ActorUser(userID), userID, "bad_qr_signature")
		return ErrInvalidDevice
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			"UPDATE auth.qr_logins SET status = 'approved' WHERE id_hash = $1 AND status = 'claimed'", hashSecret(id))
		if err != nil {
			return fmt.Errorf("approve QR request: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrQRInvalid
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopePlatform, Action: "qr.approve", Target: deviceID, Outcome: audit.Success,
		})
	})
}

// DenyQR refuses a request. It needs no signature, because a denial grants nothing.
func (s *Service) DenyQR(ctx context.Context, userID, deviceID, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE auth.qr_logins SET status = 'denied'
		 WHERE id_hash = $1 AND user_id = $2 AND device_id = $3 AND status = 'claimed'`, hashSecret(id), userID, deviceID)
	if err != nil {
		return fmt.Errorf("deny QR request: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrQRInvalid
	}
	return nil
}

// QRResult is what a poll returns. UserID is set once, on the poll that collects
// an approval.
type QRResult struct {
	Status string
	UserID string
	// MFA is whether the approving device can vouch for a second factor.
	MFA      bool
	ClientID string
	Device   *DeviceInfo
}

// PollQR reports a request's state to whoever holds its poll secret. Collecting
// an approval spends it, so it yields one session. kind must match, so a pairing
// the user approved cannot be collected as a browser sign-in.
func (s *Service) PollQR(ctx context.Context, kind, poll string) (QRResult, error) {
	var r QRResult
	var pending []byte
	err := s.pool.QueryRow(ctx,
		`UPDATE auth.qr_logins q SET status = 'consumed'
		 FROM auth.devices d
		 WHERE d.id = q.device_id AND d.revoked_at IS NULL
		   AND q.poll_hash = $1 AND q.kind = $2 AND q.status = 'approved' AND q.expires_at > now()
		 RETURNING q.user_id, d.mfa_capable, q.client_id, q.pending_device`,
		hashSecret(poll), kind).Scan(&r.UserID, &r.MFA, &r.ClientID, &pending)
	if err == nil {
		r.Status = QRApproved
		if pending != nil {
			r.Device = &DeviceInfo{}
			if err := json.Unmarshal(pending, r.Device); err != nil {
				return QRResult{}, fmt.Errorf("decode device: %w", err)
			}
		}
		return r, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return QRResult{}, fmt.Errorf("collect QR request: %w", err)
	}

	var status string
	var expires time.Time
	err = s.pool.QueryRow(ctx, "SELECT status, expires_at FROM auth.qr_logins WHERE poll_hash = $1 AND kind = $2", hashSecret(poll), kind).Scan(&status, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return QRResult{}, ErrQRInvalid
	}
	if err != nil {
		return QRResult{}, fmt.Errorf("load QR request: %w", err)
	}
	// Still approved here means the collection above refused it: the approving
	// device was revoked in between.
	if !expires.After(time.Now()) || status == "consumed" || status == QRApproved {
		return QRResult{Status: QRExpired}, nil
	}
	return QRResult{Status: status}, nil
}

// CollectPairing finishes a second device's enrollment after a poll collects
// its approval. It inherits the approver's strength, no more.
func (s *Service) CollectPairing(ctx context.Context, r QRResult, tenant string) (DeviceTokens, error) {
	if r.Device == nil {
		return DeviceTokens{}, ErrQRInvalid
	}
	client, err := s.directClient(r.ClientID)
	if err != nil {
		return DeviceTokens{}, err
	}
	device, err := parseDevice(*r.Device)
	if err != nil {
		return DeviceTokens{}, err
	}
	return s.completeDeviceLogin(ctx, deviceLogin{
		client: client, device: device, userID: r.UserID, tenant: tenant, mfa: r.MFA, approved: true,
	})
}
