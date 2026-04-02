package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config menyimpan semua konfigurasi service yang dibaca dari environment variables.
type Config struct {
	// --- Cloudflare Credentials ---
	CFApiToken  string // API Token dengan permission Zone:WAF:Edit dan Zone:Analytics:Read
	CFZoneID    string // Zone ID domain yang diproteksi
	CFAccountID string // Account ID Cloudflare
	CFRulesetID string // Custom Ruleset ID (dari GET /zones/{id}/rulesets)
	CFRuleID    string // Rule ID spesifik yang akan di-toggle (rule "allow")

	// --- Threshold & Timing ---
	RPSThreshold     float64       // Batas RPS sebelum mitigasi aktif (default: 1000)
	TriggerDuration  time.Duration // Berapa lama RPS harus breach sebelum trigger (default: 2m)
	CooldownDuration time.Duration // Berapa lama RPS harus stabil sebelum recovery (default: 15m)

	// --- Polling ---
	PollInterval time.Duration // Interval polling ke Cloudflare API (default: 60s)

	// --- Telegram ---
	TelegramBotToken string // Bot token dari @BotFather
	TelegramChatID   string // Chat ID group (biasanya negatif, misal: -1001234567890)
}

// Load membaca konfigurasi dari environment variables.
// Akan return error jika ada required variable yang tidak diset.
func Load() (*Config, error) {
	cfg := &Config{}

	// --- Required fields ---
	required := []struct {
		key  string
		dest *string
	}{
		{"CF_API_TOKEN", &cfg.CFApiToken},
		{"CF_ZONE_ID", &cfg.CFZoneID},
		{"CF_ACCOUNT_ID", &cfg.CFAccountID},
		{"CF_RULESET_ID", &cfg.CFRulesetID},
		{"CF_RULE_ID", &cfg.CFRuleID},
	}

	for _, r := range required {
		val := os.Getenv(r.key)
		if val == "" {
			return nil, fmt.Errorf("required environment variable %q is not set", r.key)
		}
		*r.dest = val
	}

	// --- Optional fields dengan default values ---
	var err error

	cfg.RPSThreshold, err = parseFloat("RPS_THRESHOLD", "1000")
	if err != nil {
		return nil, err
	}

	triggerMin, err := parseInt("TRIGGER_DURATION_MINUTES", "2")
	if err != nil {
		return nil, err
	}
	cfg.TriggerDuration = time.Duration(triggerMin) * time.Minute

	cooldownMin, err := parseInt("COOLDOWN_DURATION_MINUTES", "15")
	if err != nil {
		return nil, err
	}
	cfg.CooldownDuration = time.Duration(cooldownMin) * time.Minute

	pollSec, err := parseInt("POLL_INTERVAL_SECONDS", "60")
	if err != nil {
		return nil, err
	}
	cfg.PollInterval = time.Duration(pollSec) * time.Second

	// Validasi: poll interval minimum 30 detik untuk menghindari abuse API
	if cfg.PollInterval < 30*time.Second {
		return nil, fmt.Errorf("POLL_INTERVAL_SECONDS must be >= 30, got %d", pollSec)
	}

	// --- Telegram (opsional) ---
	cfg.TelegramBotToken = os.Getenv("TELEGRAM_BOT_TOKEN")
	cfg.TelegramChatID = os.Getenv("TELEGRAM_CHAT_ID")

	// Validasi: jika salah satu diset, keduanya harus diset
	if (cfg.TelegramBotToken == "") != (cfg.TelegramChatID == "") {
		return nil, fmt.Errorf(
			"both TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set together, or both left empty",
		)
	}

	return cfg, nil
}

// TelegramEnabled mengembalikan true jika konfigurasi Telegram lengkap.
func (c *Config) TelegramEnabled() bool {
	return c.TelegramBotToken != "" && c.TelegramChatID != ""
}

// --- Helpers ---

func parseFloat(envKey, defaultVal string) (float64, error) {
	raw := getEnvOrDefault(envKey, defaultVal)
	val, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid value for %s=%q: must be a number", envKey, raw)
	}
	if val <= 0 {
		return 0, fmt.Errorf("invalid value for %s=%q: must be > 0", envKey, raw)
	}
	return val, nil
}

func parseInt(envKey, defaultVal string) (int, error) {
	raw := getEnvOrDefault(envKey, defaultVal)
	val, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid value for %s=%q: must be an integer", envKey, raw)
	}
	if val <= 0 {
		return 0, fmt.Errorf("invalid value for %s=%q: must be > 0", envKey, raw)
	}
	return val, nil
}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}