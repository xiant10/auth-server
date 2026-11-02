// Package config loads the service configuration from environment variables.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Config is the validated service configuration.
type Config struct {
	ListenAddr string
	// PublicURL is the external base URL and the JWT issuer.
	PublicURL   string
	DatabaseURL string
	// DevMode enables the password grant. It is refused unless PublicURL is
	// localhost.
	DevMode bool

	// SigningKeyCurrent and SigningKeyNext are PEM-encoded P-256 private keys.
	SigningKeyCurrent string
	SigningKeyNext    string

	// ClientsFile is the reviewed YAML list of OAuth clients.
	ClientsFile string
	// TOTPKey is the 32-byte AES key for stored TOTP secrets. Empty in dev mode
	// means a throwaway key.
	TOTPKey []byte
	// DefaultRegion applies to phone numbers with no country code.
	DefaultRegion string
	// TrustProxy reads the client IP from the ingress's X-Forwarded-For.
	TrustProxy bool

	LiveKitURL       string
	LiveKitAPIKey    string
	LiveKitAPISecret string
}

// Load reads and validates the configuration through getenv.
func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		ListenAddr:        getenv("AUTH_LISTEN_ADDR"),
		PublicURL:         strings.TrimRight(getenv("AUTH_PUBLIC_URL"), "/"),
		DatabaseURL:       getenv("DATABASE_URL"),
		SigningKeyCurrent: getenv("AUTH_SIGNING_KEY_CURRENT"),
		SigningKeyNext:    getenv("AUTH_SIGNING_KEY_NEXT"),
		ClientsFile:       getenv("AUTH_CLIENTS_FILE"),
		DefaultRegion:     getenv("AUTH_DEFAULT_REGION"),
		TrustProxy:        getenv("AUTH_TRUST_PROXY") == "true",
		LiveKitURL:        getenv("LIVEKIT_URL"),
		LiveKitAPIKey:     getenv("LIVEKIT_API_KEY"),
		LiveKitAPISecret:  getenv("LIVEKIT_API_SECRET"),
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8081"
	}
	if cfg.DefaultRegion == "" {
		cfg.DefaultRegion = "CN"
	}
	if encoded := getenv("AUTH_TOTP_KEY"); encoded != "" {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(key) != 32 {
			return Config{}, errors.New("AUTH_TOTP_KEY must be 32 bytes of base64")
		}
		cfg.TOTPKey = key
	}
	switch getenv("AUTH_DEV_MODE") {
	case "", "false":
	case "true":
		cfg.DevMode = true
	default:
		return Config{}, errors.New("AUTH_DEV_MODE must be true or false")
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	required := map[string]string{
		"AUTH_PUBLIC_URL":    c.PublicURL,
		"DATABASE_URL":       c.DatabaseURL,
		"AUTH_CLIENTS_FILE":  c.ClientsFile,
		"LIVEKIT_URL":        c.LiveKitURL,
		"LIVEKIT_API_KEY":    c.LiveKitAPIKey,
		"LIVEKIT_API_SECRET": c.LiveKitAPISecret,
	}
	for name, value := range required {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	public, err := url.Parse(c.PublicURL)
	if err != nil || public.Host == "" {
		return fmt.Errorf("AUTH_PUBLIC_URL is not a valid URL: %q", c.PublicURL)
	}
	if c.DevMode {
		if !isLocalhost(public.Hostname()) {
			return fmt.Errorf("AUTH_DEV_MODE requires a localhost AUTH_PUBLIC_URL, got %q", c.PublicURL)
		}
		return nil
	}
	if public.Scheme != "https" {
		return errors.New("AUTH_PUBLIC_URL must use https outside dev mode")
	}
	if c.SigningKeyCurrent == "" {
		return errors.New("AUTH_SIGNING_KEY_CURRENT is required outside dev mode")
	}
	if c.TOTPKey == nil {
		return errors.New("AUTH_TOTP_KEY is required outside dev mode")
	}
	if len(c.LiveKitAPISecret) < 32 || strings.HasPrefix(c.LiveKitAPISecret, "change-me") {
		return errors.New("LIVEKIT_API_SECRET must be a real secret of 32 or more characters outside dev mode")
	}
	return nil
}

func isLocalhost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
