package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"waf-attacker-automator/internal/cloudflare"
	"waf-attacker-automator/internal/config"
	"waf-attacker-automator/internal/monitor"
	"waf-attacker-automator/internal/notify"
)

// version diisi saat build menggunakan ldflags:
// go build -ldflags="-X main.version=1.0.0" ./cmd/main.go
var version = "dev"

func main() {
	// ---------------------------------------------------------------------------
	// Logger Setup
	// Gunakan JSON handler untuk production (mudah di-parse oleh log aggregator).
	// Ganti ke NewTextHandler jika ingin output yang lebih mudah dibaca di terminal.
	// ---------------------------------------------------------------------------
	logLevel := slog.LevelInfo
	if os.Getenv("LOG_LEVEL") == "debug" {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	slog.Info("WAF Automator starting", "version", version)

	// ---------------------------------------------------------------------------
	// Configuration
	// ---------------------------------------------------------------------------
	cfg, err := config.Load()
	if err != nil {
		slog.Error("Configuration failed — check your environment variables", "error", err)
		printConfigHelp()
		os.Exit(1)
	}

	slog.Info("Configuration loaded",
		"zone_id", cfg.CFZoneID,
		"ruleset_id", cfg.CFRulesetID,
		"rule_id", cfg.CFRuleID,
		"rps_threshold", cfg.RPSThreshold,
		"trigger_duration", cfg.TriggerDuration,
		"cooldown_duration", cfg.CooldownDuration,
		"poll_interval", cfg.PollInterval,
		"telegram_enabled", cfg.TelegramEnabled(),
	)

	// ---------------------------------------------------------------------------
	// Connectivity Check
	// Validasi API token dan konfigurasi sebelum mulai polling.
	// Lebih baik gagal cepat daripada baru ketahuan saat serangan berlangsung.
	// ---------------------------------------------------------------------------
	if err := runStartupChecks(cfg); err != nil {
		slog.Error("Startup check failed", "error", err)
		os.Exit(1)
	}

	// ---------------------------------------------------------------------------
	// Telegram Notifier (opsional)
	// ---------------------------------------------------------------------------
	var tgNotifier *notify.TelegramNotifier
	if cfg.TelegramEnabled() {
		tgNotifier = notify.NewTelegramNotifier(cfg.TelegramBotToken, cfg.TelegramChatID)

		// Kirim pesan startup ke Telegram sebagai konfirmasi service berjalan.
		startupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := tgNotifier.NotifyStartup(startupCtx, cfg.CFZoneID, version); err != nil {
			// Non-fatal: jangan stop service hanya karena Telegram tidak bisa dihubungi.
			slog.Warn("Telegram startup notification failed — continuing anyway", "error", err)
		}
		cancel()

		slog.Info("Telegram notifier initialized", "chat_id", cfg.TelegramChatID)
	} else {
		slog.Warn("Telegram notifier disabled — set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to enable")
	}

	// ---------------------------------------------------------------------------
	// Monitor Setup
	// ---------------------------------------------------------------------------
	m := monitor.New(cfg, tgNotifier)

	// ---------------------------------------------------------------------------
	// Graceful Shutdown
	// Tangkap SIGINT (Ctrl+C) dan SIGTERM (Docker stop / Kubernetes termination).
	// Context akan di-cancel saat sinyal diterima, yang akan menghentikan Run() loop.
	// ---------------------------------------------------------------------------
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Jalankan monitor di goroutine terpisah agar kita bisa handle shutdown dengan bersih.
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.Run(ctx)
	}()

	// Tunggu hingga ctx dibatalkan (sinyal shutdown diterima).
	<-ctx.Done()

	slog.Info("Shutdown signal received — waiting for monitor to stop gracefully...")

	// Beri waktu maksimal 30 detik untuk monitor menyelesaikan tick yang sedang berjalan.
	shutdownTimer := time.NewTimer(30 * time.Second)
	defer shutdownTimer.Stop()

	select {
	case <-done:
		slog.Info("Monitor stopped cleanly")
	case <-shutdownTimer.C:
		slog.Warn("Monitor did not stop within 30s — forcing exit")
	}

	// Kirim notifikasi shutdown ke Telegram jika ada.
	if tgNotifier != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tgNotifier.NotifyShutdown(shutdownCtx, cfg.CFZoneID, m.PollCount())
	}

	slog.Info("WAF Automator exited", "total_polls", m.PollCount())
}

// ---------------------------------------------------------------------------
// Startup Checks
// ---------------------------------------------------------------------------

// runStartupChecks melakukan validasi koneksi ke Cloudflare sebelum polling dimulai.
// Mencegah silent failure saat rule ID atau token salah.
func runStartupChecks(cfg *config.Config) error {
	slog.Info("Running startup connectivity checks...")

	checkCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check 1: Validasi WAF rule bisa diakses dan ambil expression-nya.
	// Ini sekaligus memvalidasi CF_API_TOKEN, CF_ZONE_ID, CF_RULESET_ID, CF_RULE_ID.
	wafClient := cloudflare.NewWAFClient(
		cfg.CFApiToken,
		cfg.CFZoneID,
		cfg.CFRulesetID,
		cfg.CFRuleID,
	)

	expr, err := wafClient.GetRuleExpression(checkCtx, cfg.CFRuleID)
	if err != nil {
		return fmt.Errorf("WAF connectivity check failed: %w\n"+
			"  → Pastikan CF_API_TOKEN punya permission 'Zone:WAF:Edit'\n"+
			"  → Cek CF_ZONE_ID, CF_RULESET_ID, dan CF_RULE_ID sudah benar", err)
	}

	slog.Info("WAF rule validated",
		"rule_id", cfg.CFRuleID,
		"expression_preview", truncate(expr, 80),
	)

	// Check 2: Validasi GraphQL Analytics API bisa diakses.
	gqlClient := cloudflare.NewGraphQLClient(cfg.CFApiToken, cfg.CFZoneID)
	_, err = gqlClient.GetAllowRuleRPS(checkCtx, cfg.CFRuleID)
	if err != nil {
		// Warning saja — GraphQL mungkin tidak return data jika zone baru atau traffic 0.
		// Tapi error auth/permission harus dianggap fatal.
		if isAuthError(err) {
			return fmt.Errorf("GraphQL connectivity check failed (auth error): %w\n"+
				"  → Pastikan CF_API_TOKEN punya permission 'Zone:Analytics:Read'", err)
		}
		slog.Warn("GraphQL check returned non-critical error — will continue",
			"error", err,
		)
	} else {
		slog.Info("GraphQL Analytics API validated")
	}

	slog.Info("All startup checks passed ✅")
	return nil
}

// isAuthError memeriksa apakah error adalah authentication/authorization error.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "401") || contains(msg, "403") ||
		contains(msg, "unauthorized") || contains(msg, "forbidden")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// printConfigHelp mencetak panduan konfigurasi environment variables ke stderr.
func printConfigHelp() {
	help := `
Required environment variables:
  CF_API_TOKEN     Cloudflare API token (needs Zone:WAF:Edit + Zone:Analytics:Read)
  CF_ZONE_ID       Zone ID of the domain to protect
  CF_ACCOUNT_ID    Cloudflare Account ID
  CF_RULESET_ID    Custom WAF Ruleset ID (from GET /zones/{id}/rulesets)
  CF_RULE_ID       Rule ID to toggle (the "allow" rule)

Optional environment variables (with defaults):
  RPS_THRESHOLD              1000    RPS limit before mitigation triggers
  TRIGGER_DURATION_MINUTES   2       Minutes RPS must stay above threshold
  COOLDOWN_DURATION_MINUTES  15      Minutes RPS must stay below threshold to recover
  POLL_INTERVAL_SECONDS      60      How often to poll Cloudflare (min: 30)
  LOG_LEVEL                  info    Set to "debug" for verbose logging

Telegram (optional, both required if either is set):
  TELEGRAM_BOT_TOKEN         Bot token from @BotFather
  TELEGRAM_CHAT_ID           Group chat ID (negative number, e.g. -1001234567890)

How to get Ruleset ID and Rule ID:
  curl -X GET "https://api.cloudflare.com/client/v4/zones/ZONE_ID/rulesets" \
    -H "Authorization: Bearer YOUR_TOKEN" | jq '.result[] | {id, name, phase}'
`
	fmt.Fprintln(os.Stderr, help)
}