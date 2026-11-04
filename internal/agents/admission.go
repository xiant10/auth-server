// Package agents owns room admission and agent grants.
package agents

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"t10-auth-server/internal/audit"
	"t10-auth-server/internal/ids"
)

// RoomTokenTTL bounds how long a room token can open a new connection.
// LiveKit refreshes the token of a connected participant on its own.
const RoomTokenTTL = 10 * time.Minute

// Errors returned by Admit.
var (
	ErrInvalidRoom    = errors.New("invalid room name")
	ErrTenantMismatch = errors.New("tenant does not match the token")
	ErrNoTenant       = errors.New("token has no active tenant")
)

var roomPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// conversationRoom starts the name of a call inside one person's conversation.
const conversationRoom = "conv-"

// roomNameFor namespaces a room. Tenant IDs hold no underscore after their
// prefix, so this cannot collide across tenants whatever the room name contains.
// A conversation's room also takes the user: session IDs can be guessed, and
// anyone in a room hears the call, so nobody else may land in it.
func roomNameFor(tenantID, userID, room string) string {
	if strings.HasPrefix(room, conversationRoom) {
		return tenantID + "__" + userID + "__" + room
	}
	return tenantID + "__" + room
}

// validRoom refuses "__" as well as a bad name: it separates the parts of a
// namespaced room, so a caller who could send it could name another person's
// conversation room as a plain one.
func validRoom(room string) bool {
	return roomPattern.MatchString(room) && !strings.Contains(room, "__")
}

// Membership is the directory check admission depends on.
type Membership interface {
	CheckActive(ctx context.Context, userID, tenantID string) error
}

// Signer signs the participant assertion and delegated tokens.
type Signer interface {
	SignAssertion(userID, tenantID, audience string, ttl time.Duration) (string, time.Time, error)
	MintDelegated(d Delegation, ttl time.Duration) (string, time.Time, error)
}

// Delegation is what a token minted from a grant says: whose rights, which
// runtime acts, under which grant, and why the run is running.
type Delegation struct {
	UserID, TenantID, RuntimeID, GrantID, Scope string
	Audiences                                   []string
	Trigger, Automation                         string
}

// LiveKit holds the only copy of the LiveKit API secret.
type LiveKit struct {
	URL       string
	APIKey    string
	APISecret string
}

// Service is the agents module.
type Service struct {
	pool       *pgxpool.Pool
	membership Membership
	signer     Signer
	liveKit    LiveKit
	runtimes   []Runtime
	exchangers []string
	// toolGateway turns on each runtime's tool_audience, where the tool gateway
	// runs. Off, every token carries its grant's audiences, as in Light.
	toolGateway bool
}

// UseToolGateway makes tokens for runtimes with a tool_audience good only at
// the tool gateway. Turn it on only where the gateway runs and every harness
// points its MCP entries at it, or their tool calls stop.
func (s *Service) UseToolGateway(on bool) { s.toolGateway = on }

// AllowExchange names the services that may exchange a delegated token for one
// with another audience on its grant.
func (s *Service) AllowExchange(services []string) { s.exchangers = slices.Clone(services) }

// NewService builds the module. With no voice runtime listed, admission creates
// no grant, which suits an agent that doesn't call agent-pi.
func NewService(pool *pgxpool.Pool, membership Membership, signer Signer, liveKit LiveKit, runtimes []Runtime) *Service {
	return &Service{pool: pool, membership: membership, signer: signer, liveKit: liveKit, runtimes: runtimes}
}

// GrantAttribute is the participant attribute holding a call's grant ID. It sits
// in the LiveKit-signed token, so a client can't alter it, and the ID is useless
// without the runtime's credentials.
const GrantAttribute = "t10.grant"

// Admission is the wire response of POST /v1/rooms/admission.
type Admission struct {
	RoomToken  string `json:"room_token"`
	RoomName   string `json:"room_name"`
	Identity   string `json:"identity"`
	Assertion  string `json:"assertion"`
	ServerURL  string `json:"server_url,omitempty"`
	ExpiresAt  string `json:"expires_at"`
	CanPublish bool   `json:"can_publish"`
}

// Admit lets a user into a room of their token's tenant. The tenant comes from
// the token: a requested tenant may only repeat it.
func (s *Service) Admit(ctx context.Context, userID, tokenTenant, requestedTenant, room string) (*Admission, error) {
	if tokenTenant == "" {
		return nil, ErrNoTenant
	}
	if requestedTenant != "" && requestedTenant != tokenTenant {
		s.deny(ctx, userID, tokenTenant, room, "tenant_mismatch")
		return nil, ErrTenantMismatch
	}
	if !validRoom(room) {
		return nil, ErrInvalidRoom
	}
	if err := s.membership.CheckActive(ctx, userID, tokenTenant); err != nil {
		s.deny(ctx, userID, tokenTenant, room, "membership")
		return nil, err
	}

	roomName := roomNameFor(tokenTenant, userID, room)
	var attributes map[string]string
	var grant *Grant
	if voice, ok := s.voiceRuntime(); ok {
		grant = &Grant{
			ID: ids.New("grt"), RuntimeID: ServiceID(voice.Name), UserID: userID, TenantID: tokenTenant,
			Actions: voice.Actions, Audiences: voice.Audiences, Constraints: []byte("{}"), Depth: 1, Trigger: TriggerVoice,
		}
		attributes = map[string]string{GrantAttribute: grant.ID}
	}
	const canPublish = true
	roomToken, expires, err := s.mintRoomToken(userID, roomName, canPublish, attributes)
	if err != nil {
		return nil, err
	}
	assertion, _, err := s.signer.SignAssertion(userID, tokenTenant, "room:"+roomName, RoomTokenTTL)
	if err != nil {
		return nil, err
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if grant != nil {
			if err := insertGrant(ctx, tx, grant, DefaultGrantTTL); err != nil {
				return err
			}
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor: audit.ActorUser(userID), Scope: audit.ScopeTenant(tokenTenant), Action: "room.admit",
			Target: roomName, Outcome: audit.Success,
		})
	})
	if err != nil {
		return nil, err
	}
	return &Admission{
		RoomToken:  roomToken,
		RoomName:   roomName,
		Identity:   userID,
		Assertion:  assertion,
		ServerURL:  s.liveKit.URL,
		ExpiresAt:  expires.UTC().Format(time.RFC3339),
		CanPublish: canPublish,
	}, nil
}

func (s *Service) deny(ctx context.Context, userID, tenantID, room, reason string) {
	err := audit.Write(context.WithoutCancel(ctx), s.pool, audit.Entry{
		Actor: audit.ActorUser(userID), Scope: audit.ScopeTenant(tenantID), Action: "room.admit", Target: room,
		Outcome: audit.Denied, Detail: map[string]any{"reason": reason},
	})
	if err != nil {
		slog.ErrorContext(ctx, "audit write failed", "error", err)
	}
}

type videoGrant struct {
	RoomJoin       bool   `json:"roomJoin"`
	Room           string `json:"room"`
	CanPublish     bool   `json:"canPublish"`
	CanSubscribe   bool   `json:"canSubscribe"`
	CanPublishData bool   `json:"canPublishData"`
}

type roomClaims struct {
	jwt.RegisteredClaims
	Video      videoGrant        `json:"video"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// mintRoomToken signs a LiveKit access token: HS256 under the API secret, with
// the API key as issuer and the participant identity as subject.
func (s *Service) mintRoomToken(identity, room string, canPublish bool, attributes map[string]string) (string, time.Time, error) {
	now := time.Now()
	expires := now.Add(RoomTokenTTL)
	claims := roomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.liveKit.APIKey,
			Subject:   identity,
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expires),
		},
		Video: videoGrant{
			RoomJoin:       true,
			Room:           room,
			CanPublish:     canPublish,
			CanSubscribe:   true,
			CanPublishData: true,
		},
		Attributes: attributes,
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.liveKit.APISecret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign room token: %w", err)
	}
	return signed, expires, nil
}
