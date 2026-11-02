package identity

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Client types.
const (
	ClientPublic       = "public"
	ClientConfidential = "confidential"
)

// Client is one entry of the reviewed client list.
type Client struct {
	ID string `yaml:"id"`
	// Name is what the mobile app shows when asked to approve this client.
	Name         string   `yaml:"name"`
	Type         string   `yaml:"type"`
	RedirectURIs []string `yaml:"redirect_uris"`
	// SecretSHA256 is the hex hash of a confidential client's secret.
	SecretSHA256 string        `yaml:"secret_sha256"`
	IdleTTL      time.Duration `yaml:"idle_ttl"`
	// AbsoluteTTL of zero means no absolute limit.
	AbsoluteTTL time.Duration `yaml:"absolute_ttl"`
	// DirectLogin allows the password API. Only the mobile app may have it,
	// because it is the one client t10 builds with its own login screen.
	DirectLogin bool `yaml:"direct_login"`
}

// LoadClients reads and validates the client list.
func LoadClients(path string) ([]Client, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read clients file: %w", err)
	}
	var doc struct {
		Clients []Client `yaml:"clients"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse clients file: %w", err)
	}
	seen := map[string]bool{}
	for _, c := range doc.Clients {
		if c.ID == "" || seen[c.ID] {
			return nil, fmt.Errorf("client id %q is empty or repeated", c.ID)
		}
		seen[c.ID] = true
		if c.Type != ClientPublic && c.Type != ClientConfidential {
			return nil, fmt.Errorf("client %s: type must be public or confidential", c.ID)
		}
		if c.Type == ClientConfidential && c.SecretSHA256 == "" {
			return nil, fmt.Errorf("client %s: confidential clients need secret_sha256", c.ID)
		}
		if c.IdleTTL <= 0 {
			return nil, fmt.Errorf("client %s: idle_ttl is required", c.ID)
		}
	}
	if len(doc.Clients) == 0 {
		return nil, errors.New("clients file lists no clients")
	}
	return doc.Clients, nil
}

// AllowsRedirect matches exactly, except that a native client's 127.0.0.1
// entry accepts any port, because it listens on an ephemeral one (RFC 8252).
func (c Client) AllowsRedirect(uri string) bool {
	got, err := url.Parse(uri)
	if err != nil || got.Fragment != "" || got.User != nil {
		return false
	}
	for _, allowed := range c.RedirectURIs {
		if uri == allowed {
			return true
		}
		want, err := url.Parse(allowed)
		if err != nil || c.Type != ClientPublic || want.Hostname() != "127.0.0.1" {
			continue
		}
		if got.Scheme == want.Scheme && got.Hostname() == "127.0.0.1" && got.Path == want.Path && got.RawQuery == want.RawQuery {
			return true
		}
	}
	return false
}

func (c Client) checkSecret(secret string) bool {
	if c.Type != ClientConfidential {
		return true
	}
	sum := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(c.SecretSHA256)) == 1
}
