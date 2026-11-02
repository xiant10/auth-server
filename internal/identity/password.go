package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// MinPasswordLength is the shortest password accepted.
const MinPasswordLength = 10

// ErrWeakPassword means a password fails the policy.
var ErrWeakPassword = errors.New("password must be at least 10 characters and not a common one")

//go:embed common_passwords.txt
var commonPasswordList string

var commonPasswords = func() map[string]bool {
	set := map[string]bool{}
	for line := range strings.Lines(commonPasswordList) {
		set[strings.TrimSpace(line)] = true
	}
	return set
}()

// checkPassword applies the password policy. names are the account's sign-in
// names, which a password must not repeat.
func checkPassword(password string, names ...string) error {
	length := utf8.RuneCountInString(password)
	if length < MinPasswordLength {
		return ErrWeakPassword
	}
	lower := strings.ToLower(password)
	first, _ := utf8.DecodeRuneInString(lower)
	if commonPasswords[lower] || strings.Count(lower, string(first)) == length {
		return ErrWeakPassword
	}
	for _, name := range names {
		if lower == strings.ToLower(strings.TrimSpace(name)) {
			return ErrWeakPassword
		}
	}
	return nil
}

type argonParams struct {
	memoryKiB uint32
	time      uint32
	threads   uint8
}

const (
	argonSaltLen = 16
	argonKeyLen  = 32
)

// Hasher hashes passwords with Argon2id. Each call costs real CPU and memory,
// so it caps how many run at once on this replica.
type Hasher struct {
	params argonParams
	slots  chan struct{}
	dummy  string
}

// NewHasher returns a Hasher that runs at most concurrency hashes at once.
func NewHasher(concurrency int) (*Hasher, error) {
	h := &Hasher{
		params: argonParams{memoryKiB: 64 * 1024, time: 3, threads: 4},
		slots:  make(chan struct{}, concurrency),
	}
	dummy, err := h.Hash(context.Background(), "unused-dummy-password")
	if err != nil {
		return nil, err
	}
	h.dummy = dummy
	return h, nil
}

// Hash returns a PHC-format Argon2id hash, carrying its parameters.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	rand.Read(salt) // Never fails; see crypto/rand.
	key, err := h.derive(ctx, password, salt, h.params)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.params.memoryKiB, h.params.time, h.params.threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify reports whether password matches encoded, using the parameters
// stored with the hash.
func (h *Hasher) Verify(ctx context.Context, password, encoded string) (bool, error) {
	params, salt, want, err := parseHash(encoded)
	if err != nil {
		return false, err
	}
	key, err := h.derive(ctx, password, salt, params)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(key, want) == 1, nil
}

// NeedsRehash reports whether a hash predates the current parameters.
func (h *Hasher) NeedsRehash(encoded string) bool {
	params, _, _, err := parseHash(encoded)
	return err != nil || params != h.params
}

// VerifyDummy spends the same time as a real check, so an unknown name cannot
// be told from a wrong password by timing.
func (h *Hasher) VerifyDummy(ctx context.Context, password string) {
	_, _ = h.Verify(ctx, password, h.dummy)
}

func (h *Hasher) derive(ctx context.Context, password string, salt []byte, p argonParams) ([]byte, error) {
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return argon2.IDKey([]byte(password), salt, p.time, p.memoryKiB, p.threads, argonKeyLen), nil
}

func parseHash(encoded string) (argonParams, []byte, []byte, error) {
	var p argonParams
	var version int
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, nil, nil, errors.New("not an argon2id hash")
	}
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, nil, nil, errors.New("unsupported argon2 version")
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memoryKiB, &p.time, &p.threads); err != nil {
		return p, nil, nil, fmt.Errorf("parse argon2 parameters: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, fmt.Errorf("decode salt: %w", err)
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, fmt.Errorf("decode key: %w", err)
	}
	return p, salt, key, nil
}
