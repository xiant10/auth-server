package config

import (
	"strings"
	"testing"
)

func env(overrides map[string]string) func(string) string {
	values := map[string]string{
		"AUTH_PUBLIC_URL":          "https://auth.example.com/",
		"DATABASE_URL":             "postgres://db/auth",
		"AUTH_SIGNING_KEY_CURRENT": "pem",
		"AUTH_CLIENTS_FILE":        "clients.yaml",
		"AUTH_TOTP_KEY":            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"LIVEKIT_URL":              "wss://lk.example.com",
		"LIVEKIT_API_KEY":          "key",
		"LIVEKIT_API_SECRET":       "a-real-secret-of-32-or-more-characters",
	}
	for k, v := range overrides {
		values[k] = v
	}
	return func(k string) string { return values[k] }
}

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":8081" {
		t.Errorf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.PublicURL != "https://auth.example.com" {
		t.Errorf("PublicURL keeps its trailing slash: %q", cfg.PublicURL)
	}
}

func TestLoad_Rejects(t *testing.T) {
	tests := []struct {
		name     string
		override map[string]string
		want     string
	}{
		{"dev mode on a public host", map[string]string{"AUTH_DEV_MODE": "true"}, "localhost"},
		{"dev mode lookalike host", map[string]string{"AUTH_DEV_MODE": "true", "AUTH_PUBLIC_URL": "http://localhost.evil.example"}, "localhost"},
		{"dev mode not a boolean", map[string]string{"AUTH_DEV_MODE": "1"}, "AUTH_DEV_MODE"},
		{"plain http outside dev", map[string]string{"AUTH_PUBLIC_URL": "http://auth.example.com"}, "https"},
		{"no signing key outside dev", map[string]string{"AUTH_SIGNING_KEY_CURRENT": ""}, "AUTH_SIGNING_KEY_CURRENT"},
		{"no TOTP key outside dev", map[string]string{"AUTH_TOTP_KEY": ""}, "AUTH_TOTP_KEY"},
		{"short TOTP key", map[string]string{"AUTH_TOTP_KEY": "AAAA"}, "AUTH_TOTP_KEY"},
		{"example LiveKit secret outside dev", map[string]string{"LIVEKIT_API_SECRET": "change-me-to-a-32-plus-character-secret"}, "LIVEKIT_API_SECRET"},
		{"short LiveKit secret outside dev", map[string]string{"LIVEKIT_API_SECRET": "short"}, "LIVEKIT_API_SECRET"},
		{"no database", map[string]string{"DATABASE_URL": ""}, "DATABASE_URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(env(tt.override))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want mention of %q", err, tt.want)
			}
		})
	}
}

func TestLoad_DevModeOnLocalhost(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		"AUTH_DEV_MODE":            "true",
		"AUTH_PUBLIC_URL":          "http://localhost:8081",
		"AUTH_SIGNING_KEY_CURRENT": "",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.DevMode {
		t.Error("DevMode not set")
	}
}
