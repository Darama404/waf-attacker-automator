package config

import (
	"fmt"
	"os"
)

// Config menyimpan semua konfigurasi service yang dibaca dari environment variables.
type Config struct {
	// --- Cloudflare Credentials ---
	CFApiToken  string // API Token: Zone:WAF:Edit + Zone:Analytics:Read + Zone:Zone:Read
	CFAccountID string // Account ID — digunakan untuk filter zone saat listing

	// --- Rule Discovery ---
	// Nama rule yang akan di-toggle di SEMUA zone.
	// Harus sama persis dengan field "description" di Cloudflare dashboard.
	AllowRuleName string // default: "allow-countries-ip"

	// Zone yang dikecualikan dari automasi (opsional).
	// Format: comma-separated domain names, e.g. "staging.com,internal.com"
	ExcludedZones []string

	// --- Webhook Server ---
	WebhookPort string // Port untuk listen webhook dari Prometheus Alertmanager (default: 8080)

	// --- Telegram ---
	TelegramBotToken string
	TelegramChatID   string
}

// Load membaca konfigurasi dari environment variables.
func Load() (*Config, error) {
	cfg := &Config{}

	// --- Required ---
	required := []struct {
		key  string
		dest *string
	}{
		{"CF_API_TOKEN", &cfg.CFApiToken},
		{"CF_ACCOUNT_ID", &cfg.CFAccountID},
	}

	for _, r := range required {
		val := os.Getenv(r.key)
		if val == "" {
			return nil, fmt.Errorf("required environment variable %q is not set", r.key)
		}
		*r.dest = val
	}

	// --- Rule Discovery ---
	cfg.AllowRuleName = getEnvOrDefault("ALLOW_RULE_NAME", "allow-countries-ip")

	// Excluded zones: parse comma-separated
	if raw := os.Getenv("EXCLUDED_ZONES"); raw != "" {
		cfg.ExcludedZones = splitAndTrim(raw, ",")
	}

	// --- Webhook Server ---
	cfg.WebhookPort = getEnvOrDefault("WEBHOOK_PORT", "8080")

	// --- Telegram (opsional) ---
	cfg.TelegramBotToken = os.Getenv("TELEGRAM_BOT_TOKEN")
	cfg.TelegramChatID = os.Getenv("TELEGRAM_CHAT_ID")

	if (cfg.TelegramBotToken == "") != (cfg.TelegramChatID == "") {
		return nil, fmt.Errorf(
			"TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must both be set, or both left empty",
		)
	}

	return cfg, nil
}

// IsZoneExcluded memeriksa apakah sebuah domain dikecualikan dari automasi.
func (c *Config) IsZoneExcluded(domainName string) bool {
	for _, excluded := range c.ExcludedZones {
		if excluded == domainName {
			return true
		}
	}
	return false
}

// TelegramEnabled mengembalikan true jika Telegram dikonfigurasi.
func (c *Config) TelegramEnabled() bool {
	return c.TelegramBotToken != "" && c.TelegramChatID != ""
}

// --- Helpers ---



func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitAndTrim(s, sep string) []string {
	var result []string
	for _, part := range splitString(s, sep) {
		trimmed := trimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func splitString(s, sep string) []string {
	var parts []string
	start := 0
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			parts = append(parts, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}